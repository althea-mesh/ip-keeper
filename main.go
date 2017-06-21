package main

import (
	"encoding/binary"
	"errors"
	"log"
	"net"

	"fmt"

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

func bytesToPublicKey(bytes []byte) [32]byte {
	var publicKey [32]byte
	copy(publicKey[:], bytes)
	return publicKey
}

func makeUvarint(n uint64) []byte {
	b := make([]byte, 10)
	i := binary.PutUvarint(b, n)
	return b[:i]
}

type IPRecord struct {
	Number int
	IP     net.IPNet
	PubKey [32]byte
}

func main() {
	// Open the my.db data file in your current directory.
	// It will be created if it doesn't exist.
	db, err := bolt.Open("ipKeeper.db", 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		db.Close()
	}()

	Init(db, "10.0.0.0/16", 2)

	ip, err := GetIP(db, [32]byte{0x3b, 0xee, 0xb8, 0xd0, 0x2, 0x7c, 0x31, 0x38, 0x1a, 0xc2, 0x28, 0xdc, 0xe1, 0x23, 0x2d, 0x62, 0x9c, 0xcd, 0x68, 0x1e, 0xde, 0x7d, 0x45, 0xbb, 0xc0, 0xec, 0x10, 0x87, 0x94, 0x8d, 0xfe, 0xa})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ip)

	ip, err = GetIP(db, [32]byte{0x4b, 0xee, 0xb8, 0xd0, 0x2, 0x7c, 0x31, 0x38, 0x1a, 0xc2, 0x28, 0xdc, 0xe1, 0x23, 0x2d, 0x62, 0x9c, 0xcd, 0x68, 0x1e, 0xde, 0x7d, 0x45, 0xbb, 0xc0, 0xec, 0x10, 0x87, 0x94, 0x8d, 0xfe, 0xa})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ip)

	ip, err = GetIP(db, [32]byte{0x2b, 0xee, 0xb8, 0xd0, 0x2, 0x7c, 0x31, 0x38, 0x1a, 0xc2, 0x28, 0xdc, 0xe1, 0x23, 0x2d, 0x62, 0x9c, 0xcd, 0x68, 0x1e, 0xde, 0x7d, 0x45, 0xbb, 0xc0, 0xec, 0x10, 0x87, 0x94, 0x8d, 0xfe, 0xa})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ip)

	ip, err = GetIP(db, [32]byte{0x2b, 0xee, 0xb8, 0xd0, 0x2, 0x7c, 0x31, 0x38, 0x1a, 0xc2, 0x28, 0xdc, 0xe1, 0x23, 0x2d, 0x62, 0x9c, 0xcd, 0x68, 0x1e, 0xde, 0x7d, 0x45, 0xbb, 0xc0, 0xec, 0x10, 0x87, 0x94, 0x8d, 0xfe, 0xa})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ip)
}

func Init(db *bolt.DB, parentRange string, newBits int) error {
	return db.Update(func(tx *bolt.Tx) error {
		config, err := tx.CreateBucket([]byte("Config"))
		_, err = tx.CreateBucket([]byte("PubKey<->Number"))
		_, err = tx.CreateBucket([]byte("AvailableList"))
		if err != nil {
			return err
		}

		err = config.Put([]byte("ParentRange"), []byte(parentRange))
		if err != nil {
			return err
		}

		err = config.Put([]byte("NewBits"), makeUvarint(uint64(newBits)))
		if err != nil {
			return err
		}

		err = config.Put([]byte("RangeSequence"), makeUvarint(uint64(0)))
		if err != nil {
			return err
		}

		return nil
	})
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

		newBits, _ := binary.Uvarint(n)

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

	num, _ := binary.Uvarint(n)
	// Last address in range is broadcast address
	hostMax := cidr.AddressCount(parent)

	if num < hostMax {
		config.Put([]byte("RangeSequence"), makeUvarint(uint64(num+1)))
		return num, nil
	}
	return 0, errors.New("No available IPs in range")
}
