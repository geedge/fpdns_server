package datastruct

type ResolverFp struct {
	Dnssec        bool  `json:"dnssec"`
	RDbit         bool  `json:"rd0"`
	QnameEncode   bool  `json:"0x20"`
	QueryMerge    int   `json:"merge_dup"`
	MaxNsDepth    int   `json:"max_ns_depth"`
	MaxCnameDepth int   `json:"max_cname_depth"`
	RetryLimit    int   `json:"retry_limit"`
	FetchLimit    int   `json:"fetch_limit"`
	MaxQueryNum   int   `json:"max_query_num"`
	TimeoutStart  int64 `json:"timeout_start"`
	TimeoutEnd    int64 `json:"timeout_end"`
}

type InitSet map[int]struct{}
type TaskMap map[int]*ResolverFp
type ResultMap map[int]ResolverFp

var Init_set = make(InitSet)
var Task_map = make(TaskMap)
var Result_map = make(ResultMap)
