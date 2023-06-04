---
title: "Understanding io.LimitReader"
date: 2023-06-03
categories: [Programming, Go]
tags: [GO]
image:
  path: /assets/img/Go/Go.png
---

Welcome to this comprehensive tutorial on GoLang's io.LimitReader! Today, we are going to discuss a powerful, yet often overlooked feature of the Go programming language, the io.LimitReader. We'll try to answer some crucial questions including what it is, why we need it, how it works and how to use it properly.

## **What is LimitReader?**

io.LimitReader is a function provided by Go's io package. This function returns a Reader that reads from the provided reader, but only up to a specified number of bytes. The underlying implementation is a structure called a LimitedReader.

```go
// LimitReader returns a Reader that reads from r
// but stops with EOF after n bytes.
// The underlying implementation is a *LimitedReader.
func LimitReader(r Reader, n int64) Reader { return &LimitedReader{r, n} }
```

## **Why Use a LimitReader?**

LimitReader is a great way to manage and control data when you're dealing with an unknown or potentially large amount of data. It's often used when you want to read from a stream but you don't want to allocate too much memory or you want to avoid a potential denial of service (DoS) attack by limiting the amount of data you read.

## **How Does LimitReader Work?**

The LimitReader function in Go's **`io`** package returns a structure called a **`LimitedReader`**. This structure contains two key components:

- **`R`**: This is the underlying reader from which data is read.
- **`N`**: This is the maximum number of bytes that can be read from the underlying reader **`R`**.

```go
type LimitedReader struct {
	R Reader // underlying reader
	N int64  // max bytes remaining
}
```

The LimitedReader struct has a method called **`Read`** that receives a byte slice as a parameter. The **`Read`** method in turn reads data into this byte slice from the underlying reader, **`R`**. However, it does this in accordance with the limit specified by **`N`**.

In practice, the **`Read`** method will perform the following steps:

1. If the remaining byte limit **`N`** is less than or equal to zero, it immediately returns zero and an EOF error. This means there are no more bytes to read.
2. If the length of the byte slice is greater than **`N`**, it reduces the slice to match the size of **`N`**. This is to ensure that the number of bytes read does not exceed the maximum limit.
3. Finally, the **`Read`** method calls the **`Read`** method of the underlying reader **`R`**, reducing **`N`** by the number of bytes read.

```go
func (l *LimitedReader) Read(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, EOF
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
	}
	n, err = l.R.Read(p)
	l.N -= int64(n)
	return
}
```

In short, the **`LimitedReader`** is a mechanism that allows reading from a Reader but with a cap on the number of bytes that can be read. The **`Read`** method within **`LimitedReader`** helps enforce this cap, while delegating the actual reading operation to the underlying reader.

## **Using LimitReader**

Now, let's dive into a practical example to demonstrate how to use the io.LimitReader in a Go program.

```go
package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func main() {
	// Create a strings.Reader
	sr := strings.NewReader("io.limitReader example")

	// Create an io.Reader with LimitReader
	r := io.LimitReader(sr, 8)

	// Define a bufio.Reader which implements and contains io.Reader interface
	br := bufio.NewReader(r)

	// Create a byte slice with a certain size
	buf := make([]byte, 30)

	// Read from the reader
	n, err := br.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print the result
	fmt.Printf("Whole byte size: %d. Read byte size: %d\n", len(buf), n)
	fmt.Printf("Read byte: %s\n", string(buf[:n]))
}
```

In this code snippet, we first create a strings.Reader with the given string "io.limitReader example". Then we create a LimitReader with a limit of 8 bytes, meaning we can only read up to 8 bytes from the original string.

The bufio.NewReader is then defined, which takes the LimitReader as an argument. We then create a byte slice with a length of 30 and read from the reader.

Running this program will result in the output:

```go
Whole byte size: 30. Read byte size: 8
Read byte: io.limit
```

## **Conclusion**

This example demonstrates the functionality of LimitReader, which allows you to control the amount of data to be read from a reader, thus providing a useful mechanism for managing data read operations.

We hope this tutorial has helped you understand Go's io.LimitReader better. Remember, a good developer not only writes code, but also knows how to manage resources effectively. 

Happy coding!