package main

import "net/http"

func main() {
	api := http.NewServeMux()
	api.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	http.ListenAndServe(":8080", api)
}
