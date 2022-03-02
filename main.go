package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"golang.org/x/crypto/sha3"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	genCount = uint64(0)

	pattern    = kingpin.Arg("pattern", "The Regex pattern to look for").Regexp()
	matchCount = kingpin.Arg("match-count", "The number of matches to look for until termination").Default("1").Int()
	cpuCount   = kingpin.Flag("num-cpu", "The number of CPU cores to run on").Default(fmt.Sprint(runtime.NumCPU())).Int()
)

func init() {
	kingpin.Parse()
}

func generate(wg *sync.WaitGroup, re *regexp.Regexp) {

	for {

		publicKey, secretKey, err := ed25519.GenerateKey(nil)
		checkErr(err)

		onionAddress := encodePublicKey(publicKey)

		// If a matching address is found, save key and notify wait group
		if re.MatchString(onionAddress) == true {
			fmt.Println(onionAddress)
			save(onionAddress, publicKey, expandSecretKey(secretKey))
			wg.Done()
		}
		atomic.AddUint64(&genCount, 1)
	}
}

func expandSecretKey(secretKey ed25519.PrivateKey) [64]byte {

	hash := sha512.Sum512(secretKey[:32])
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash

}

func encodePublicKey(publicKey ed25519.PublicKey) string {

	// checksum = H(".onion checksum" || pubkey || version)
	var checksumBytes bytes.Buffer
	checksumBytes.Write([]byte(".onion checksum"))
	checksumBytes.Write([]byte(publicKey))
	checksumBytes.Write([]byte{0x03})
	checksum := sha3.Sum256(checksumBytes.Bytes())

	// onion_address = base32(pubkey || checksum || version)
	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write([]byte(publicKey))
	onionAddressBytes.Write([]byte(checksum[:2]))
	onionAddressBytes.Write([]byte{0x03})
	onionAddress := base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes())

	return strings.ToLower(onionAddress)

}

func save(onionAddress string, publicKey ed25519.PublicKey, secretKey [64]byte) {
	os.MkdirAll(onionAddress, 0700)

	secretKeyFile := append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), secretKey[:]...)
	checkErr(ioutil.WriteFile(onionAddress+"/hs_ed25519_secret_key", secretKeyFile, 0600))

	publicKeyFile := append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), publicKey...)
	checkErr(ioutil.WriteFile(onionAddress+"/hs_ed25519_public_key", publicKeyFile, 0600))

	checkErr(ioutil.WriteFile(onionAddress+"/hostname", []byte(onionAddress+".onion"), 0600))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	runtime.GOMAXPROCS(*cpuCount)

	var wg sync.WaitGroup
	wg.Add(*matchCount)

	for i := 0; i < *cpuCount; i++ {
		go generate(&wg, *pattern)
	}

	tick := time.NewTicker(time.Second * 10)
	go func() {

		start := time.Now()
		for range tick.C {
			currTime := time.Now()
			tdiff := currTime.Sub(start)
			rate := float64(genCount) / tdiff.Seconds()

			fmt.Printf("[%08d]: Computed %d Keys (Rate: %f per Second)\n", int(tdiff.Seconds()), genCount, rate)
		}

	}()

	wg.Wait()
	tick.Stop()

}
