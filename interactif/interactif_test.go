package interactif

import "testing"

// test this package
type EmulateInteractif struct {
	LineToRead string
	Printed    string
}

func (ei *EmulateInteractif) ReadLine() string {
	return ei.LineToRead
}

func (ei *EmulateInteractif) Print(s string) {
	ei.Printed = s
}

// test the function AskSecretI
func TestAskSecretI(t *testing.T) {
	//define test case
	var testcases = []struct {
		name           string
		emulateInput   string
		expectedOutput string
	}{
		{"test1", "1", "1"},
		{"test2", "2", "2"},
		{"test3", "3", "3"},
		{"test4", "4", "4"},
	}
	//run the test cases
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ei := &EmulateInteractif{LineToRead: tc.emulateInput}
			if AskSecretI(ei) != tc.expectedOutput {
				t.Errorf("AskSecretI() = %s; want %s", AskSecretI(ei), tc.expectedOutput)
			}
		})
	}
}
