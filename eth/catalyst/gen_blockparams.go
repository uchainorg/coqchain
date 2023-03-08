// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package catalyst

import (
	"encoding/json"
	"errors"

	"github.com/uchainorg/coqchain/common"
	"github.com/uchainorg/coqchain/common/hexutil"
)

var _ = (*assembleBlockParamsMarshaling)(nil)

// MarshalJSON marshals as JSON.
func (a assembleBlockParams) MarshalJSON() ([]byte, error) {
	type assembleBlockParams struct {
		ParentHash common.Hash    `json:"parentHash"    gencodec:"required"`
		Timestamp  hexutil.Uint64 `json:"timestamp"     gencodec:"required"`
	}
	var enc assembleBlockParams
	enc.ParentHash = a.ParentHash
	enc.Timestamp = hexutil.Uint64(a.Timestamp)
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (a *assembleBlockParams) UnmarshalJSON(input []byte) error {
	type assembleBlockParams struct {
		ParentHash *common.Hash    `json:"parentHash"    gencodec:"required"`
		Timestamp  *hexutil.Uint64 `json:"timestamp"     gencodec:"required"`
	}
	var dec assembleBlockParams
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.ParentHash == nil {
		return errors.New("missing required field 'parentHash' for assembleBlockParams")
	}
	a.ParentHash = *dec.ParentHash
	if dec.Timestamp == nil {
		return errors.New("missing required field 'timestamp' for assembleBlockParams")
	}
	a.Timestamp = uint64(*dec.Timestamp)
	return nil
}
