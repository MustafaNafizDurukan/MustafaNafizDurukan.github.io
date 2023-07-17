---
title: "Writing to Multiple Destinations in Go with io.MultiWriter"
date: 2023-07-17
categories: [Programming, Go]
tags: [GO]
image:
  path: /assets/img/Go/gopher_microphone.png
---

The Go programming language, well-regarded for its simplicity and efficiency, has an extensive standard library containing a plethora of built-in packages. Among these, the **`io`** package plays a critical role due to its wide-ranging functionality, handling I/O operations. Today, our attention will be directed towards the **`MultiWriter`** type, an important feature of the **`io`** package.

## **What is MultiWriter?**

**`MultiWriter`** is a type in the **`io`** package of Go that facilitates writing to multiple output destinations using a single write operation. This functionality is akin to the Unix **`tee`** command, enabling simultaneous writing to several Writers. The primary objective of **`MultiWriter`** is to reduce redundancy and enhance code readability by removing the need to call the write function multiple times for different output writers.

Here is the construction of the **`multiWriter`**:

```go
type multiWriter struct {
	writers []Writer
}
```

Each **`multiWriter`** contains a slice of **`Writer`** types, denoting the multiple destinations where data should be written.

## **Why Use MultiWriter?**

**`MultiWriter`** becomes an important tool in scenarios where you want to write the same data to multiple locations. For example, logging is a common use case. You may want to write log data both to a log file and the console at the same time.

Benefits of using **`MultiWriter`** include:

1. **Code Efficiency**: Instead of writing separate blocks of code to handle each writer, you can use **`MultiWriter`** to write to multiple writers with a single write call, making your code more efficient and cleaner.
2. **Logging and Monitoring**: **`MultiWriter`** is extremely useful in logging and monitoring processes. It allows for simultaneous writing of log or monitoring data to different destinations, such as a local log file, a network server, or standard output.

## **How Does MultiWriter Work?**

The **`io.MultiWriter`** function in Go's **`io`** package returns a writer that duplicates its writes to all provided writers, much like the Unix **`tee(1)`** command.

This is achieved through the use of the **`multiWriter`** structure and its methods. 

Let's break down the components of this structure:

- **`writers`**: This is a slice of **`Writer`** interfaces. Each **`Writer`** in this slice is a destination where data will be written.

```go
type multiWriter struct {
	writers []Writer
}
```

### Write

```go
func (t *multiWriter) Write(p []byte) (n int, err error) {
	for _, w := range t.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = ErrShortWrite
			return
		}
	}
	return len(p), nil
}
```

This method writes a byte slice to each writer in the **`writers`** slice, one at a time. It returns the number of bytes written and an error if one occurs. If a writer returns an error, the **`Write`** operation stops immediately and does not continue to the remaining writers in the list. This method also ensures that the complete byte slice is written to each writer - if not, it returns **`ErrShortWrite`**.

### WriteString

```go
func (t *multiWriter) WriteString(s string) (n int, err error) {
	var p []byte // lazily initialized if/when needed
	for _, w := range t.writers {
		if sw, ok := w.(StringWriter); ok {
			n, err = sw.WriteString(s)
		} else {
			if p == nil {
				p = []byte(s)
			}
			n, err = w.Write(p)
		}
		if err != nil {
			return
		}
		if n != len(s) {
			err = ErrShortWrite
			return
		}
	}
	return len(s), nil
}
```

This method is similar to **`Write`**, but accepts a string instead of a byte slice. It optimizes the write operation by using the **`WriteString`** method of the **`StringWriter`** interface, if a writer supports it.

### MultiWriter

The **`MultiWriter`** function uses the **`multiWriter`** struct to create a writer that writes to all provided writers:

```go
func MultiWriter(writers ...Writer) Writer {
	allWriters := make([]Writer, 0, len(writers))
	for _, w := range writers {
		if mw, ok := w.(*multiWriter); ok {
			allWriters = append(allWriters, mw.writers...)
		} else {
			allWriters = append(allWriters, w)
		}
	}
	return &multiWriter{allWriters}
}
```

When **`MultiWriter`** is called, it creates a slice of writers. If any of the provided writers is itself a **`multiWriter`**, **`MultiWriter`** flattens it into its constituent writers, thus ensuring that each write operation is performed directly on the underlying writers and not on intermediate **`multiWriter`** instances. It then returns a **`multiWriter`** that writes to all these writers.

## **Using MultiWriter**

Here's an illustrative example on how to use **`MultiWriter`**, featuring writing an XML encoding of a slice of **`Person`** structs to multiple destinations:

```go
type Person struct {
	Name    string
	Surname string
}

func (p *Person) Write(b []byte) (n int, err error) {
	fmt.Printf("Write method ran. Name of person is %s \n", p.Name)
	return len(b), nil
}

func main() {
	persons := []Person{
		{Name: "name1", Surname: "surname1"},
		{Name: "name2", Surname: "surname2"},
		{Name: "name3", Surname: "surname3"},
		{Name: "name4", Surname: "surname4"},
	}

	f, err := os.Create("1.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	buf := bytes.NewBuffer(make([]byte, 0))

	w := io.MultiWriter(f, buf, os.Stdout)
	for i := range persons {
		w = io.MultiWriter(w, &persons[i])
	}

	enc := xml.NewEncoder(w)
	if err := enc.Encode(persons); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Buffer string:", buf.String())
}
```

In this code, we first create a slice of **`Person`** structs, with each **`Person`** having a **`Write`** method that fulfills the **`io.Writer`** interface. We then create a file, a byte buffer, and a **`MultiWriter`** that writes to the file, the buffer, and standard output (**`os.Stdout`**).

We loop over the **`persons`** slice, creating a new **`MultiWriter`** for each **`Person`** that writes to all previous destinations plus the current **`Person`**.

We then create an XML encoder that writes to our final **`MultiWriter`**, and encode our **`persons`** slice to it. The encoding is written to all our destinations: the file, the buffer, standard output, and each **`Person`**. The final line of our program prints the contents of our buffer, which should contain the XML encoding.

```go
<Person><Name>name1</Name><Surname>surname1</Surname></Person><Person><Name>name2</Name><Surname>surname2</Surname></Person><Person><Name>name3</Name><Surname>surname3</Surname></Person><Person><Name>name4</Name><Surname>surname4</Surname></Person>
Write method ran. Name of person is name1 
Write method ran. Name of person is name2 
Write method ran. Name of person is name3 
Write method ran. Name of person is name4
```

In the output, you'll see that the XML encoding is written to the console, and also that the **`Write`** method is called on each **`Person`** object. This shows that **`io.MultiWriter`** indeed writes to all provided writers, making it a useful tool for writing the same data to multiple destinations.

## **Conclusion**

The **`MultiWriter`** type in the Go's **`io`** package is a powerful and versatile tool that offers the ability to write the same data to multiple locations in a straightforward manner. By reducing redundancy, optimizing resources, and enhancing logging and monitoring, **`MultiWriter`** can be a valuable addition to your Go programming toolbox. 

Happy coding!