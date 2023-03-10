// Copyright 2020 The coqchain Authors
// This file is part of the coqchain library.
//
// The coqchain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The coqchain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the coqchain library. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/uchainorg/coqchain/tests/fuzzers/les"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: debug <file>\n")
		fmt.Fprintf(os.Stderr, "Example\n")
		fmt.Fprintf(os.Stderr, "	$ debug ../crashers/4bbef6857c733a87ecf6fd8b9e7238f65eb9862a\n")
		os.Exit(1)
	}
	crasher := os.Args[1]
	data, err := ioutil.ReadFile(crasher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading crasher %v: %v", crasher, err)
		os.Exit(1)
	}
	les.Fuzz(data)
}
