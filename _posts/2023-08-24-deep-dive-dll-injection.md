---
title: "Deep Dive into DLL Injection: A Static Analysis with PEStudio and OllyDebug"
date: 2023-08-24
categories: [Techniques, DLL Injection]
tags: [DLL Injection]
image:
  path: /assets/img/deep-dive-dll-injection/cover.png
---

## Why is DLL Injection used?

Most cracked programs, cheats used in games, malicious software, etc., utilize a method known as DLL Injection to modify specific data types (int, float, etc.) in the victim software, conceal malicious activity, or enhance the functionality of the victim software.

If you have two different processes running and you want one to access the address space of the other, the operating system will prevent this. This is because the OS allocates separate memory areas to each process. This can vary with the operating system and can be done through methods like paging, segmentation, etc. During paging, when a process is created, a new frame is added to the operating system's paging table (if we think of the paging table as a table, it corresponds to each row). Each frame of the paging table holds a different memory address. The retrieved addresses undergo specific operations to give us the Physical Address. Therefore, each process's address is stored in a different area in memory.

Thus, if any process tries to access an address outside its allocated memory addresses, the operating system will prevent it.

## What is DLL (Dynamic Link Libraries)?

DLLs are similar to EXE files, but they can't be run directly. They are used to execute specific tasks of processes within a single file to save memory. If a process wants to perform a particular function, it can obtain it from the necessary DLLs.

## How is DLL Injection done?

Windows APIs offer functions like connecting to another program, opening sockets, etc. We will proceed using such methods while performing DLL Injection. Our goal is to execute our LoadLibrary() function on the victim process.

The parameter of LoadLibrary() will be the name of our DLL, which means we need to allocate memory space in the target process. We will do this using the VirtualAllocEx() function.

We will divide DLL Injection into 4 steps:

1. Execute the Process
2. Allocate memory in the Process
3. Write the DLL's address to the allocated memory
4. Run the DLL

![Untitled](/assets/img/deep-dive-dll-injection/Untitled.png)

### **Process Execution**

To inject our target file, it must be running, i.e., it must be converted into a process. We do this using OpenProcess().

```c
DWORD access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
OpenProcess(access, FALSE, ProcessId);
```

1. Here, we obtained permissions like creating threads, reading the process's memory, and writing to the process's memory.
2. It asks whether to transfer these properties if the process creates a new process; we gave 'false' as we don't want that.
3. ProcessId is the id of the process we want to open.

Instead of the values we provided to Access, we could have used PROCESS_ALL_ACCESS, but I prefer to be precise.

### **Memory Allocation in the Process**

Before injecting our DLL, we need to allocate memory inside the victim process to write our DLL's name. For this, we have the VirtualAllocEx() function.

Now a question arises: how much space should be allocated? We determine this by the length of our DLL's path +1, considering the null character at the end of the string.

```c
AllocMem = VirtualAllocEx(hProcess, NULL, sizeof(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

1. hProcess asks for the handle of the process we want to open, and we provided the value.
2. We entered NULL because we don't have a specific memory address in mind.
3. We provided the size of our DLL's path as the amount of space to allocate.
4. We defined our operation types.
5. We wrote PAGE_READWRITE because we want to perform read-write operations.
6. We will use AllocMem later.

Having created our process and allocated space inside it, we now need to write our DLL's path into the process and load it using LoadLibrary.

### **Writing to the Process**

In the previous step, we allocated space in our victim file. Now, we will write our DLL's path to the reserved space using WriteProcessMemory().

```c
WriteProcessMemory(hProcess, AllocMem, dllName, sizeof(dllName), NULL);
```

1. We provided the handle of our process.
2. We gave the area we created with VirtualAllocEx(), as it needs to know the writing area.
3. The content we want to write to the allocated memory space.
4. The size of the memory area.
5. After writing, it returns how much area it wrote to; we left it NULL as it wasn't needed.

### **DLL Execution**

Having skillfully allocated space inside the target process and inserted our DLL's name, the only remaining task is to execute the LoadLibrary function in the target Process. We will achieve this using CreateRemoteThread(), which allows us to run threads in another process.

> LoadLibraryA() is a function used to load the Kernel32.dll, exe files, and libraries.
> 

```c
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocMem, 0, 0);
```

1. hProcess is our process handle.
2. No attribute.
3. Size is 0 because our DLL will determine its size.
4. We used LoadLibraryA, which is defined in the Windows library.
5. The memory area we will write to.
6. The size of the memory area.
7. We left it NULL as the thread ID wasn't needed.

At this point, we have successfully injected our DLL into the target process. The result of our injected DLL will depend on the DLL's purpose, be it monitoring, modifying behavior, or any other function.

I hope this article has provided you with a deeper understanding of the concept and methods of DLL Injection!

## **Review**

Let's Start with Static Analysis...

We open the file with PEStudio. Once opened, let's go to the strings section and see what's inside.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled1.png)

We can observe that the program provides a sort of guide and mentions about being injected. Let's continue and look at the imported functions as well.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled2.png)

As we mentioned earlier, it uses the functions we highlighted in red (WriteProcessMemory, OpenProcess, VirtualAllocEx, LoadLibraryA). I'm convinced at this point, but I think a little more examination would be better.

Returning to the strings section in PEStudio, we see explanations for functions such as –create, --runtime, etc. So, I'll open this program with OllyDebug, providing the parameters to see what matches.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled3.png)

If you've noticed, we saw that the program took three inputs, so I provided my arguments accordingly:

1. The file I want to inject: notepad.exe.
2. Path of the DLL I want to inject.
3. I provided –create because I wanted the victim file to run before the injection.

I launched our exe on OllyDebug. Now, I'm curious about where it calls functions like VirtualAllocEx that we're familiar with.

To see the imported ones, I need to go to the import address. To view the imported functions, I press Ctrl+N.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled4.png)

Then, I follow it in the disassembler.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled5.png)

As we predicted, it has reserved space in the process, and it's likely going to proceed in the same order as we did.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled6.png)

It's written some data to the process.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled7.png)

However, we didn't use GetModuleHandleA. Here, they've added GetModuleHandleA and GetProcAddress to the mix. GetModuleHandleA takes "kernel32.dll" as a parameter. GetProcAddress takes the LoadLibraryA function as a parameter. GetProcAddress is used to determine the location of LoadLibraryA. GetModuleHandle finds the address of kernel32.dll. The address of kernel32.dll is in the stack, and GetProcAddress function fetches it and locates the address of LoadLibraryA.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled8.png)

When CreateRemoteThread is executed, let's discuss the three things that will happen:

1. A new thread will be executed within our target process.
2. The LoadLibraryA function will run inside the new thread.
3. LoadLibraryA will load our DLL into the target process's address space.

That concludes the explanation. The result is as follows:

![Untitled](/assets/img/deep-dive-dll-injection/Untitled9.png)

Using Process Hacker, we can see that OllyDebug created kinject.exe, and kinject.exe, in turn, created notepad.exe.

![Untitled](/assets/img/deep-dive-dll-injection/Untitled10.png)

## **Summary**

The article presents a detailed static analysis of a file using PEStudio. Upon examination of the strings section, it's revealed that the program offers a guide and mentions a process of injection. The article then delves into the program's imported functions, which are essential for its operation. To further analyze, the author uses OllyDebug, supplying specific parameters to observe the program's behavior. This analysis identifies the sequence in which the program injects a DLL into the notepad.exe process. The program employs functions like WriteProcessMemory, OpenProcess, VirtualAllocEx, and LoadLibraryA. A key observation is the utilization of GetModuleHandleA and GetProcAddress to determine function addresses. The article concludes by outlining the outcomes of executing CreateRemoteThread. Using Process Hacker, the cascading creation of processes is also demonstrated.