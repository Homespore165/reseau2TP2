package server

type DBRequest struct {
	QueryType  string
	Parameters []interface{}
	Response   chan DBResponse
}
