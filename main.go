package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/boltdb/bolt"
)

// Get IP
// pop off available list
// if available list empty ->
//   n = Get number of addresses in range
//   if counter greater than n, range is full
//   i = counter + 1
//   ip = get subnet for i in range
//   increment counter
//
// Release IP
//

func BytesToPublicKey(bytes []byte) [32]byte {
	var publicKey [32]byte
	copy(publicKey[:], bytes)
	return publicKey
}

type IPRecord struct {
	Number int
	IP     net.IPNet
	PubKey [32]byte
}

func main() {
	fmt.Println("hop")
}

func GetIP(db *bolt.DB, pubkey [32]byte) (*net.IPNet, error) {
	var subnet *net.IPNet
	err := db.Update(func(tx *bolt.Tx) error {
		config := tx.Bucket([]byte("Config"))

		p := config.Get([]byte("ParentRange"))
		if p == nil {
			return errors.New("Missing ParentRange from config")
		}
		_, parent, err := net.ParseCIDR(string(p))
		if err != nil {
			return err
		}

		n := config.Get([]byte("NewBits"))
		if n == nil {
			return errors.New("Missing NewBits from config")
		}

		newBits, _ := binary.Varint(n)

		num, err := getIPNumber(tx, pubkey, parent)
		if err != nil {
			return err
		}

		// Turn into an IP address
		subnet, err = cidr.Subnet(parent, int(newBits), int(num))
		if err != nil {
			return err
		}

		return nil
	})

	return subnet, err
}

func getIPNumber(tx *bolt.Tx, pubkey [32]byte, parent *net.IPNet) (uint64, error) {
	key2num := tx.Bucket([]byte("PubKey<->Number"))
	config := tx.Bucket([]byte("Config"))
	avail := tx.Bucket([]byte("AvailableList"))

	var num uint64

	// Try to find existing entry for key
	n := key2num.Get(pubkey[:])
	if n != nil {
		num, _ := binary.Uvarint(n)
		return num, nil
	}

	// Try to get number from list of newly available numbers
	c := avail.Cursor()
	_, n = c.First()

	if n != nil {
		num, _ := binary.Uvarint(n)
		return num, nil
	}

	// Try to get new number in sequence
	n = config.Get([]byte("RangeSequence"))
	if n == nil {
		return 0, errors.New("Missing RangeSequence from config")
	}

	num, _ = binary.Uvarint(n)

	if num+1 < cidr.AddressCount(parent) {
		var b []byte
		binary.PutUvarint(b, num+1)
		config.Put([]byte("RangeSequence"), b)
		return num, nil
	}
	return 0, errors.New("No available IPs in range")
}
