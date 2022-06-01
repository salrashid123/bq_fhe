package neg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

func neg(x []byte) ([]byte, error) {

	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN12QP109]
	//params.T =  0x3ee0001 //65929217₁₀

	evaluator := bfv.NewEvaluator(params)

	rX := &bfv.Ciphertext{}

	err := rX.UnmarshalBinary(x)
	if err != nil {
		return nil, err
	}

	XNeg := evaluator.NegNew(rX)
	XNegBytes, err := XNeg.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return XNegBytes, nil
}

const ()

var ()

func init() {}

func FHE_NEG(w http.ResponseWriter, r *http.Request) {

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

			xstr, ok := r[0].(string)
			if !ok {
				bqResp.ErrorMessage = "Invalid key type. expected string"
				bqResp.Replies = nil
				break
			}

			x, err := base64.StdEncoding.DecodeString(xstr)
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
						ec, err := neg(x)
						if err != nil {
							bqResp.ErrorMessage = fmt.Sprintf("Error encrypting row %d", j)
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

	http.HandleFunc("/", FHE_NEG)

	server := &http.Server{
		Addr: ":8080",
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err := server.ListenAndServe()
	log.Fatalf("Unable to start Server %v", err)
}
