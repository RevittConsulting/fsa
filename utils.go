package auth

import (
	"encoding/json"
	"net/http"
	"fmt"
	"reflect"
)

type ErrResponse struct {
	Error string `json:"error"`
}

func WriteJSON(w http.ResponseWriter, v interface{}) {
	if isNil(v) {
		WriteErr(w, fmt.Errorf("not found"), http.StatusNotFound)
		return
	}

	j, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(j)
}

func WriteErr(w http.ResponseWriter, err error, code int) {
	switch err.(type) {
	default:
		w.WriteHeader(code)
		WriteJSON(w, ErrResponse{Error: err.Error()})
	}
}

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	value := reflect.ValueOf(i)
	kind := value.Kind()
	return (kind == reflect.Ptr || kind == reflect.Slice || kind == reflect.Map || kind == reflect.Func || kind == reflect.Chan || kind == reflect.Interface) && value.IsNil()
}
