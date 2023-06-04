---
title: "Understanding io.TeeReader"
date: 2023-06-04
categories: [Programming, Go]
tags: [GO]
image:
  path: /assets/img/Go/Go.png
---

In the vast library of Go's built-in packages, the **`io`** package stands out due to its sheer utility. Today, we'll be focusing on a particular function in this package - the **`io.TeeReader`** function.

# **What is TeeReader?**

The **`io.TeeReader`** function in Go creates a new reader that simultaneously reads data from a source reader and writes the same data to a writer. You can think of it as a "T" junction in a pipeline, where data is flowing in from one direction and is split into two directions.

The function signature is as follows:

```go
func TeeReader(r Reader, w Writer) Reader
```

This function takes a **`Reader`** and a **`Writer`** as arguments and returns a **`Reader`**. The returned **`Reader`** behaves exactly like the original **`Reader`** with the added behavior of writing to the provided **`Writer`**.

# **Why Use TeeReader?**

The power of **`io.TeeReader`** comes from its ability to "spy" on data as it's being read, without modifying the flow of data or the interface of the **`Reader`**. This makes it ideal for situations where you need to process the same data twice. Examples include logging raw data being read, calculating checksums on the fly, or displaying progress during data transfers, as you'll see in the upcoming example.

# **How Does TeeReader Work?**

The **`io.TeeReader`** function in Go's **`io`** package returns a new **`Reader`** that is essentially a structure called a **`teeReader`**. This structure has two significant components:

- **`r`**: This is the underlying **`Reader`** from which data is read.
- **`w`**: This is the **`Writer`** to which data read from **`r`** is written.

Here's how it is structured:

```go
type teeReader struct {
	r Reader // underlying reader
	w Writer // writer to write data to
}
```

The **`teeReader`** struct implements a **`Read`** method that receives a byte slice as a parameter. The **`Read`** method reads data into this byte slice from the underlying reader (**`r`**) and concurrently writes the same data to the **`Writer`** (**`w`**).

In practical terms, the **`Read`** method works in the following steps:

1. The **`Read`** method calls the **`Read`** method of the underlying **`Reader`** (**`r`**) to read the data into the byte slice. This method returns the number of bytes read and any error encountered.
2. If the number of bytes read (**`n`**) is more than zero, the **`Read`** method writes those bytes to the **`Writer`** (**`w`**). If an error occurs during writing, the method immediately returns the number of bytes written and the encountered error.
3. The **`Read`** method then returns the number of bytes read and any error encountered during reading.

Here's how the **`Read`** method of **`teeReader`** is defined:

```go
func (t *teeReader) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		if n, err := t.w.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return
}
```

In essence, the **`TeeReader`** is a conduit that allows data to be read from a **`Reader`** and simultaneously written to a **`Writer`**. The **`Read`** method within **`teeReader`** helps manage this process, allowing you to "spy" on data as it passes through without modifying the flow or the interface of the **`Reader`**.

# **Using TeeReader**

Now that we've seen how **`io.TeeReader`** works, let's dive into a practical example.

Imagine you are downloading a large file and you want to calculate its checksum on-the-fly to verify the integrity of the file after download. Also, you want to display the progress of the download. This is a perfect scenario to use **`io.TeeReader`**.

In the example below, we'll download a gzip file, save it locally, and use **`io.TeeReader`** to display the download progress:

```go
type progress struct {
	total uint64
}

func (p *progress) Write(b []byte) (int, error) {
	p.total += uint64(len(b))
	fmt.Printf("Downloaded %d bytes...\n", p.total)
	return len(b), nil
}

func main() {
	res, err := http.Get("http://storage.googleapis.com/books/ngrams/books/googlebooks-eng-all-5gram-20120701-0.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	localFile, err := os.OpenFile("file.txt", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer localFile.Close()

	gzipReader, err := gzip.NewReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	teeReader := io.TeeReader(gzipReader, &progress{})

	if _, err := io.Copy(localFile, teeReader); err != nil {
		log.Fatal(err)
	}
}
```

In this code, we've created a **`progress`** struct that implements the **`io.Writer`** interface. It's used to calculate the total bytes read from the gzip file. The **`Write`** method is called every time **`io.TeeReader`** reads data, thereby tracking the download progress.

Running this program will result in the output:

```go
...
...
Downloading 328.406250 MB...
Downloading 328.437500 MB...
Downloading 328.468750 MB...
Downloading 328.500000 MB...
Downloading 328.531250 MB...
Downloading 328.562500 MB...
Downloading 328.593750 MB...
Downloading 328.625000 MB...
Downloading 328.656250 MB...
Downloading 328.687500 MB...
Downloading 328.718750 MB...
Downloading 328.750000 MB...
Downloading 328.781250 MB...
Downloading 328.812500 MB...
Downloading 328.843750 MB...
Downloading 328.869534 MB...
```

By using **`io.TeeReader`**, we're able to easily add progress reporting functionality without changing how the original reader behaves.

# **Conclusion**

Go's **`io.TeeReader`** is a powerful function that can provide real-time insights into data as it's being read. By understanding its internals and how to use it, you can enhance your data pipelines with additional, simultaneous processing steps. Happy coding!