package main

import (
	"context"
	"fmt"
	"io/ioutil"

	"flag"

	"cloud.google.com/go/bigquery"
	"github.com/google/uuid"
	"github.com/ldsec/lattigo/bfv"
)

var (
	datasetID = "fhe"
	tableID   = "xy"
)

type Location struct {
	Uid string
	X   []byte
	Y   []byte
}

func (i *Location) Save() (map[string]bigquery.Value, string, error) {
	return map[string]bigquery.Value{
		"uid": i.Uid,
		"x":   i.X,
		"Y":   i.Y,
	}, "", nil
}

func loadKey(pubFile string, secFile string) ([]byte, []byte, error) {

	var pk bfv.PublicKey
	pkBytes, err := ioutil.ReadFile(pubFile)
	if err != nil {
		return nil, nil, err
	}

	pk.UnmarshalBinary(pkBytes)

	var sk bfv.SecretKey
	skBytes, err := ioutil.ReadFile(secFile)
	if err != nil {
		return nil, nil, err
	}

	sk.UnmarshalBinary(skBytes)

	return pkBytes, skBytes, nil
}

func genKey(pubFile string, secFile string) ([]byte, []byte, error) {

	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN12QP109]
	//params.T = //0x3ee0001 //65929217₁₀

	kgen := bfv.NewKeyGenerator(params)
	riderSk, riderPk := kgen.GenKeyPair()

	pubBytes, err := riderPk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	err = ioutil.WriteFile(pubFile, pubBytes, 0640)
	if err != nil {
		return nil, nil, err
	}

	secBytes, err := riderSk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	err = ioutil.WriteFile(secFile, secBytes, 0640)
	if err != nil {
		return nil, nil, err
	}

	return pubBytes, secBytes, nil
}

func encrypt(x uint64, pub []byte) ([]byte, error) {

	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN12QP109]
	//params.T =  0x3ee0001 //65929217₁₀

	encoder := bfv.NewEncoder(params)

	var pk bfv.PublicKey

	err := pk.UnmarshalBinary(pub)
	if err != nil {
		return nil, err
	}
	encryptorPk := bfv.NewEncryptorFromPk(params, &pk)

	XPlaintext := bfv.NewPlaintext(params)
	rX := make([]uint64, 1<<params.LogN)
	rX[0] = x
	encoder.EncodeUint(rX, XPlaintext)
	XcipherText := encryptorPk.EncryptNew(XPlaintext)
	XcipherBytes, err := XcipherText.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return XcipherBytes, nil
}

func decrypt(encrypted []byte, secBytes []byte) (int64, error) {

	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN12QP109]
	//params.T =  0x3ee0001 //65929217₁₀

	encoder := bfv.NewEncoder(params)

	var sk bfv.SecretKey

	err := sk.UnmarshalBinary(secBytes)
	if err != nil {
		return 0, err
	}
	decryptorSk := bfv.NewDecryptor(params, &sk)

	var XcipherT bfv.Ciphertext
	err = XcipherT.UnmarshalBinary(encrypted)
	if err != nil {
		return 0, err
	}
	XplainT := bfv.NewPlaintext(params)
	decryptorSk.Decrypt(&XcipherT, XplainT)
	x := encoder.DecodeInt(XplainT)

	//return x[0<<1], nil
	return x[0<<1], nil
}

func add(x []byte, y []byte, pub []byte) ([]byte, error) {

	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN12QP109]
	//params.T =  0x3ee0001 //65929217₁₀

	evaluator := bfv.NewEvaluator(params)

	var pk bfv.PublicKey

	err := pk.UnmarshalBinary(pub)
	if err != nil {
		return nil, err
	}
	rX := &bfv.Ciphertext{}
	rY := &bfv.Ciphertext{}

	err = rX.UnmarshalBinary(x)
	if err != nil {
		return nil, err
	}

	err = rY.UnmarshalBinary(y)
	if err != nil {
		return nil, err
	}
	XPlusY := evaluator.AddNew(rX, rY)
	XPlusYBytes, err := XPlusY.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return XPlusYBytes, nil
}

func sub(x []byte, y []byte, pub []byte) ([]byte, error) {

	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN12QP109]
	//params.T =  0x3ee0001 //65929217₁₀

	evaluator := bfv.NewEvaluator(params)

	var pk bfv.PublicKey

	err := pk.UnmarshalBinary(pub)
	if err != nil {
		return nil, err
	}
	rX := &bfv.Ciphertext{}
	rY := &bfv.Ciphertext{}

	err = rX.UnmarshalBinary(x)
	if err != nil {
		return nil, err
	}

	err = rY.UnmarshalBinary(y)
	if err != nil {
		return nil, err
	}

	XMinuxY := evaluator.SubNew(rX, rY)
	XMinusYBytes, err := XMinuxY.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return XMinusYBytes, nil
}

func multiply(x []byte, y []byte, pub []byte) ([]byte, error) {

	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN12QP109]
	//params.T =  0x3ee0001 //65929217₁₀

	evaluator := bfv.NewEvaluator(params)

	var pk bfv.PublicKey

	err := pk.UnmarshalBinary(pub)
	if err != nil {
		return nil, err
	}
	rX := &bfv.Ciphertext{}
	rY := &bfv.Ciphertext{}

	err = rX.UnmarshalBinary(x)
	if err != nil {
		return nil, err
	}

	err = rY.UnmarshalBinary(y)
	if err != nil {
		return nil, err
	}

	XTimesY := evaluator.MulNew(rX, rY)
	XTimesYBytes, err := XTimesY.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return XTimesYBytes, nil
}

func neg(x []byte, pub []byte) ([]byte, error) {

	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN12QP109]
	//params.T =  0x3ee0001 //65929217₁₀

	evaluator := bfv.NewEvaluator(params)

	var pk bfv.PublicKey

	err := pk.UnmarshalBinary(pub)
	if err != nil {
		return nil, err
	}

	rX := &bfv.Ciphertext{}

	err = rX.UnmarshalBinary(x)
	if err != nil {
		return nil, err
	}

	XPlusY := evaluator.NegNew(rX)
	xNegate, err := XPlusY.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return xNegate, nil
}

func main() {
	projectID := flag.String("projectID", "", "(required)")

	flag.Parse()

	if *projectID == "" {
		fmt.Printf("ProjectID must be set")
		return
	}

	x := flag.Uint64("x", 3, "x")
	y := flag.Uint64("y", 2, "y")

	// pub, sec, err := genKey("pub.bin", "sec.bin")
	// if err != nil {
	// 	fmt.Printf("Err %v\n", err)
	// 	return
	// }

	pub, sec, err := loadKey("pub.bin", "sec.bin")
	if err != nil {
		fmt.Printf("Err %v\n", err)
		return
	}

	xenc, err := encrypt(*x, pub)
	if err != nil {
		fmt.Printf("Err %v\n", err)
		return
	}

	yenc, err := encrypt(*y, pub)
	if err != nil {
		fmt.Printf("Err %v\n", err)
		return
	}

	// fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(xenc))
	// fmt.Println()
	// fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(yenc))
	xplusy, err := add(xenc, yenc, pub)
	if err != nil {
		fmt.Printf("Err %v\n", err)
		return
	}

	// xtimes_xplusy, err := multiply(xenc, xplusy, pub)
	// if err != nil {
	// 	fmt.Printf("Err %v\n", err)
	// 	return
	// }

	// xneg, err := neg(xenc, pub)
	// if err != nil {
	// 	fmt.Printf("Err %v\n", err)
	// 	return
	// }

	dec, err := decrypt(xplusy, sec)
	if err != nil {
		fmt.Printf("Err %v\n", err)
		return
	}

	fmt.Printf("%v\n", dec)

	uid, _ := uuid.NewUUID()

	var items []*Location
	items = append(items, &Location{Uid: uid.String(), X: xenc, Y: yenc})

	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, *projectID)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	inserter := client.Dataset(datasetID).Table(tableID).Inserter()

	if err := inserter.Put(ctx, items); err != nil {
		fmt.Printf("Err %v\n", err)
		return
	}

}
