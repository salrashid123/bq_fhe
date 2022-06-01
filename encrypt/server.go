package encrypt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/ldsec/lattigo/bfv"
	"golang.org/x/net/http2"
)

type bqRequest struct {
	RequestId          string            `json:"requestId"`
	Caller             string            `json:"caller"`
	SessionUser        string            `json:"sessionUser"`
	UserDefinedContext map[string]string `json:"userDefinedContext"`
	Calls              [][]interface{}   `json:"calls"`
}

type bqResponse struct {
	Replies      []string `json:"replies,omitempty"`
	ErrorMessage string   `json:"errorMessage,omitempty"`
}

const (
	pubKeyURL = "https://raw.githubusercontent.com/salrashid123/bq_fhe/main/app/pub.b64"
)

var (
	pk          bfv.PublicKey
	encryptorPk bfv.Encryptor
)

func encrypt(plain float64) ([]byte, error) {

	params := bfv.DefaultParams[bfv.PN12QP109]
	XPlaintext := bfv.NewPlaintext(params)
	encoder := bfv.NewEncoder(params)
	rX := make([]uint64, 1<<params.LogN)
	rX[0] = uint64(plain)
	encoder.EncodeUint(rX, XPlaintext)
	XcipherText := encryptorPk.EncryptNew(XPlaintext)
	XcipherBytes, err := XcipherText.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return XcipherBytes, nil
}

func init() {

	var client http.Client
	resp, err := client.Get(pubKeyURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var p []byte
	if resp.StatusCode == http.StatusOK {
		p, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
	} else {
		panic(errors.New("unable to get public key from url"))
	}

	params := bfv.DefaultParams[bfv.PN12QP109]
	pubBytes, err := base64.StdEncoding.DecodeString(string(p))
	if err != nil {
		fmt.Printf("Invalid secret Key decoding %v\n", err)
	}
	err = pk.UnmarshalBinary(pubBytes)
	if err != nil {
		fmt.Printf("Invalid secret Key %v\n", err)
	}
	encryptorPk = bfv.NewEncryptorFromPk(params, &pk)

}

func FHE_ENCRYPT(w http.ResponseWriter, r *http.Request) {

	bqReq := &bqRequest{}
	bqResp := &bqResponse{}

	if err := json.NewDecoder(r.Body).Decode(&bqReq); err != nil {
		bqResp.ErrorMessage = fmt.Sprintf("External Function error: can't read POST body %v", err)
	} else {

		fmt.Printf("caller %s\n", bqReq.Caller)
		fmt.Printf("sessionUser %s\n", bqReq.SessionUser)
		fmt.Printf("userDefinedContext %v\n", bqReq.UserDefinedContext)

		wait := new(sync.WaitGroup)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		objs := make([]string, len(bqReq.Calls))

		for i, r := range bqReq.Calls {
			if len(r) != 1 {
				bqResp.ErrorMessage = fmt.Sprintf("Invalid number of input fields provided.  expected 1, got  %d", len(r))
			}

			eint, ok := r[0].(float64)
			if !ok {
				bqResp.ErrorMessage = "Invalid key type. expected string"
				bqResp.Replies = nil
				break
			}

			//  use goroutines heres but keep the order
			wait.Add(1)
			go func(j int) {
				defer wait.Done()
				for {
					select {
					case <-ctx.Done():
						return
					default:
						ec, err := encrypt(eint)
						if err != nil {
							bqResp.ErrorMessage = fmt.Sprintf("Error decrypting row %d", j)
							bqResp.Replies = nil
							cancel()
							return
						}
						objs[j] = base64.StdEncoding.EncodeToString(ec)
						return
					}
				}
			}(i)
		}

		wait.Wait()
		if bqResp.ErrorMessage != "" {
			bqResp.Replies = nil
		} else {
			bqResp.Replies = objs
		}
	}

	b, err := json.Marshal(bqResp)
	if err != nil {
		http.Error(w, fmt.Sprintf("can't convert response to JSON %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func main() {

	http.HandleFunc("/", FHE_ENCRYPT)

	server := &http.Server{
		Addr: ":8080",
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err := server.ListenAndServe()
	log.Fatalf("Unable to start Server %v", err)
}
