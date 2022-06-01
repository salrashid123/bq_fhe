package decrypt

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
	// of course you should load this from some secure source
	// GCP Secrets Engine does now allow large values so you may need to load this by some other way (eg, store encrypted using KMS keyref)
	secretKeyURL = "https://raw.githubusercontent.com/salrashid123/bq_fhe/main/app/sec.b64"
)

var (
	pk          bfv.PublicKey
	sk          bfv.SecretKey
	decryptorSk bfv.Decryptor
)

func decrypt(encrypted []byte) ([]byte, error) {

	var XcipherT bfv.Ciphertext
	err := XcipherT.UnmarshalBinary(encrypted)
	if err != nil {
		return nil, err
	}
	params := bfv.DefaultParams[bfv.PN12QP109]
	encoder := bfv.NewEncoder(params)
	XplainT := bfv.NewPlaintext(params)
	decryptorSk.Decrypt(&XcipherT, XplainT)
	x := encoder.DecodeInt(XplainT)

	// b := make([]byte, 8)
	// binary.LittleEndian.PutUint64(b, x[0<<1])

	//return x[0<<1], nil
	s := fmt.Sprintf("%v", x[0<<1])
	return []byte(s), nil
}

func init() {

	var client http.Client
	resp, err := client.Get(secretKeyURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var s []byte
	if resp.StatusCode == http.StatusOK {
		s, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
	} else {
		panic(errors.New("unable to get secret key from url"))
	}

	params := bfv.DefaultParams[bfv.PN12QP109]
	secBytes, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		fmt.Printf("Invalid secret Key decoding %v\n", err)
	}
	err = sk.UnmarshalBinary(secBytes)
	if err != nil {
		fmt.Printf("Invalid secret Key %v\n", err)
	}
	decryptorSk = bfv.NewDecryptor(params, &sk)

}

func FHE_DECRYPT(w http.ResponseWriter, r *http.Request) {

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

			estr, ok := r[0].(string)
			if !ok {
				bqResp.ErrorMessage = "Invalid key type. expected string"
				bqResp.Replies = nil
				break
			}

			e, err := base64.StdEncoding.DecodeString(estr)
			if err != nil {
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
						ec, err := decrypt(e)
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

	http.HandleFunc("/", FHE_DECRYPT)
	server := &http.Server{
		Addr: ":8080",
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err := server.ListenAndServe()
	log.Fatalf("Unable to start Server %v", err)
}
