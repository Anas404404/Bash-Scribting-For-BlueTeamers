# Intro To to Bash Scripting

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/1_GugKOJXJTFqpag3HwtdsJw.jpg)](../.gitbook/assets/1_GugKOJXJTFqpag3HwtdsJw.jpg)

### Concepts



* Bash : The Unix shell serves as an interface that allows users to interact with operating systems. This shell receives the user's commands and passes those commands to the operating system.
* Shell : allows users to communicate with the operating system. Shell is a type of user interface and is usually text-based. Shells also feature a scripting language and allow users to save commands as a written script and run this script automatically later. Bash is one of the most popular Unix shells and often comes as the default shell on
* STDIN usually represents input from the keyboard
* STDOUT represents correct output
* STDERR represents erroneous output.
* “Global Variables” are variables that can be accessed from anywhere within a script.
* “Local Variables” are variables valid only within the “Function” in which they are used.
* Environmental variables :
  * If we want to define a variable that can be accessed from anywhere during a user's session, we need to use environmental variables
  * variables that exist throughout a particular shell session and usually contain system information, user settings, or information needed for programs to run.

***

### Setting up the Bash Environment



ways to use bash on Windows operating systems

**WSL (Windows Subsystem for Linux) : Microsoft offers the Windows Subsystem for Linux feature on Windows 10 and later that lets users run Linux operating systems directly. This feature is one of the ways we can use Bash on Windows systems**

1- open a PowerShell console with Administrat or rights

```
wsl --install
```

2- access the Linux environment by locating the Ubuntu application from the Start menu and running it

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash50.png)](../.gitbook/assets/bash50.png)

3- If everything went well , it will ask us to define a username and pass before it starts the bash console.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash52.png)](../.gitbook/assets/bash52.png)

4- . Ubuntu WSL runs on its own virtual file system. It mounts the file systems of your Windows under the /mnt/ directory. So, if you want to view the files and directories on the C:/ disk of your Windows system, run the ls /mnt/c command.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash53.png)](../.gitbook/assets/bash53.png)

5- On Windows, to access your home directory in Ubuntu WSL environment, you should use “ **explorer.exe .** ”

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash54.png)](../.gitbook/assets/bash54.png)

Cygwin :

* is a software package designed to provide a POSIX compliant environment on Windows operating systems. POSIX is a set of standards that define how an operating system should work, and most Unix and Unix-like systems (Linux, BSD, etc.) follow these standards.
* Cygwin includes a library (cygwin1.dll) that translates POSIX APIs to Windows APIs, and many GNU and open-source applications which make these applications can run natively on Windows.
* Many Unix/Linux commands and services (for example, bash shell, ssh, tar, awk, make, grep, and more) become available on Windows with Cygwin

\
install Cygwin :

* Download and Run : setup-x86\_64.exe (for 64-bit systems) from the Cygwin website ( [https://www.cygwin.com](https://www.cygwin.com) ).

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash55.png)](../.gitbook/assets/bash55.png)

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash56.png)](../.gitbook/assets/bash56.png)

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash57.png)](../.gitbook/assets/bash57.png)

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash58.png)](../.gitbook/assets/bash58.png)

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash59.png)](../.gitbook/assets/bash59.png)

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash60.png)](../.gitbook/assets/bash60.png)

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash61.png)](../.gitbook/assets/bash61.png)

you can access your shell by clicking one of the **Cygwin64 Terminal** icons placed on your desktop and start menu.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash62.png)](../.gitbook/assets/bash62.png)

***

### Commands



* open New File "**hello\_word.sh"**

```
nano "hello_word.sh"
```

* The \`#!/bin/bash\` line indicates that this script should be run in Bash.\
  The \`echo\` command == Print command

```
#!/bin/bash
echo "Hello World"
```

* we have to make sure the script is executable Using This command

```
// This command adds executable permissions to `hello_world.sh`
chmod +x hello_word.sh
```

* run our script

```
./hello_word.sh
```

* created a variable named `our_variable` and assigned the value "Hello World" to it\
  To use the value of a variable, we put a dollar sign (`$`) in front of the variable name\
  Note that this definition is valid throughout the console session we are working on

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash1.png)](../.gitbook/assets/bash1.png)

To create or modify an environmental variable, we use the `export` command:

```
export NEW_VARIABLE="Hello World, Again…"
```

we created an environmental variable named `NEW_VARIABLE` and assigned it the value "Hello World, Again...". This environment variable will be available throughout the current shell session and can be read by other program

To read an environmental variable, we put a dollar sign (`$`) like a regular variable:

```
echo $PATH
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash2.png)](../.gitbook/assets/bash2.png)

env : view current environmental variables\\

*   #### “if-else-if” Structure



#### <sub>For example, in this example, it asks the user to enter a number, assigns the user-entered value to a variable, and then checks whether the value of this variable:</sub>



#### <sub>is greater than 10,</sub>



#### <sub>is equal to 10,</sub>



#### <sub>s less than 10</sub>



```
#!/bin/bash
echo "Please Input Number:"
read variable_number

if [ "$variable_number" -gt "10" ]
then
    echo "The number you entered is GREATER THAN 10"
elif [ "$variable_number" -eq "10" ]
then
    echo "The number you entered is EQUAL TO 10"
else
    echo "The number you entered is LESS THAN 10"
fi
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash4.png)](../.gitbook/assets/bash4.png)

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash-table-1.png)](../.gitbook/assets/bash-table-1.png)

#### “For” Loop



```
#!/bin/bash

for count_variable in 1 2 3 4 5
do
    echo "Current Value: $count_variable"
done               
```

* we can use strings, files and directories on the filesystem, or the output of any command as a string.

```
#!/bin/bash

for count_variable in 1 2 3 4 5
do
    echo "Current Value: $count_variable"
done

for string_variable in Torvalds Stallman Raymond Linux Bash
do
    echo "$string_variable is Great"
done

for filesystem_variable in /home/letsdefend/ex*
do
    echo "Example File: $filesystem_variable"
done

for output_variable in $(cut -d: -f1 /etc/passwd)
do
    echo "User in Passwd File: $output_variable"
done
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash8.png)](../.gitbook/assets/bash8.png)

#### “While” Loop



In this example, we created a loop as long as the value of the variable is less than or equal to 5. Then, in the "While" loop we started, we print the value to the screen in each loop and increase the value of our variable by 1. And here is the result:

```
#!/bin/bash

our_variable=1
while [ $our_variable -le 5 ]
do
    echo "Value: $our_variable"
    ((our_variable++))
done         
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash10.png)](../.gitbook/assets/bash10.png)

In the example below:

* First, we specify a “requested\_value” (“Yes”)
* Next, we start a loop that will continue as long as the "requested\_value" value is "Yes".
* We request an input from the user for each round of the loop.
* The loop continues until the user provides an input other than "Yes"

```
#!/bin/bash
requested_value="Yes"
while [ "$requested_value" = "Yes" ]
do
   echo "While is working..."
   echo "Do you want to continue? (Yes/No)"
   read requested_value
done
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash12.png)](../.gitbook/assets/bash12.png)

For this example, let's create a loop that continues unless there is a file named "test.txt" under the "/tmp" directory\
When we run the script, the loop continues until we create the "test.txt" file in the "/tmp" directory and ends when we create the file

```
#!/bin/bash
while [ ! -f /tmp/test.txt ]
do
   echo "Loop Working..."
   sleep 10
done
echo "File Found, Done."
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash14.png)](../.gitbook/assets/bash14.png)

#### “Case” Structure



“Case” allows us to perform different operations according to the different values that a variable can take\
In this example, we check if the value of the variable is equal to 1 or 2, and display different messages

```
#!/bin/bash

echo "Please input value"
read our_variable

case $our_variable in
    1 )
        echo "our_variable value is Equal To 1"
        ;;
    2 )
        echo "our_variable value is Equal To 2"
        ;;
    * )
        echo "our_variable value is NOT Equal To 1 or 2"
        ;;
esac
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash100.png)](../.gitbook/assets/bash100.png)

### Function



* represent the name of a block of code that performs a specific function.
* functions help us organize our scripts, reuse our code, and generally make our lives easier.

For example, we could create a "hello" function and have it take a name parameter:

```
hello() {
    echo "Hello, $1!"
}
```

To call this function, we can do as follows:

```
Hello "Bash"
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash101.png)](../.gitbook/assets/bash101.png)

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash102.png)](../.gitbook/assets/bash102.png)

Below is an example of :

* First, we define the “add” function. This function adds the two values sent to itself and returns the result.
* Then, we define the "multiply" function. This function multiplies the two values sent to itself and returns the result.
* Finally, we define the "calculate" function. This function, on the other hand, sends the values sent to itself to both the "add" and "multiply" functions and writes the results to the screen.

```
#!/bin/bash

# A function that adds two numbers
add() {
    local result=$(( $1 + $2 ))
    echo $result
}

# A function that multiplies two numbers
multiply() {
    local result=$(( $1 * $2 ))
    echo $result
}

# A function that uses both add and multiply functions
calculate() {
    local sum=$(add $1 $2)
    local product=$(multiply $1 $2)
    echo "The sum of $1 and $2 is $sum."
    echo "The product of $1 and $2 is $product."
}

# Call the calculate function
calculate 5 3
```

"local" and "global" variables :

* we create a global variable called 'greeting'. This variable can be accessed from anywhere - inside or outside any function
* we create a function called 'displayGreeting'. Inside this function, we create another variable called 'greeting'. But this time, we define the variable with the 'local' keyword, which means it is valid only inside this function, not outside of this function

```
#!/bin/bash

# Global variable
greeting="Hello, World!"

function displayGreeting {
    # Local variable
    local greeting="Hello, User!"
    echo $greeting # This will print "Hello, User!" because local variable takes precedence in this scope
}

# Call the function
displayGreeting

# Print the global variable
echo $greeting # This will print "Hello, World!" because the scope here has only access to the global variable
```

So what happens when we call the 'displayGreeting' function? The 'echo $greeting' code inside the function runs and says "Hello, User!" he greets us. Because the local variable inside the function rises above the global variable with the same name.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash18.png)](../.gitbook/assets/bash18.png)

#### Error Catching



* In the Bash scripting, you can use the `$?` variable to check the status of your script and catch errors.
* This variable stores the exit status of the last command executed.
* Generally, `0` represents a successful exit, while any value other than “0” indicates an error condition.

example, let's consider a script that tries to delete a file. If you try to delete the file without checking whether it exists, this may generate an error condition. We can use the variable `$?` to control this situation:

```
#!/bin/bash

rm some_file.txt
if [ $? -ne 0 ]; then
    echo "Failed to delete the file"
    exit 1
fi
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash19.png)](../.gitbook/assets/bash19.png)

#### Debugging



you can use the debug mode of the Bash scripting. You can start bash in debug mode using the `-x` parameter

```
#!/bin/bash
set -x # turn on trace mode

# some operations
echo "This is a test"
var="Hello, World!"
echo $var

set +x # turn off trace mode
                    
```

This allows you to follow what the script is doing and identify where the errors occur step-by-step.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main/.gitbook/assets/bash20.png)](../.gitbook/assets/bash20.png)

Another debugging method is to use set -e (or bash -e). set -e (or bash -e) causes the script to stop when the return value of any command in the Bash script is non-zero (it means if the script fails)

```
#!/bin/bash
set -e  # stop script execution on failure

# This command will succeed
echo "This command will succeed"
var="Hello, World!"
echo $var

# This command will fail (assuming file_does_not_exist.txt does not exist)
echo "Trying to display the contents of a file that does not exist..."
cat file_does_not_exist.txt

echo "This message will not be printed because the script already exited"
```

As you can see, the script exits before the last line since we are using "-e"

Useful Articles

\{% embed url="[https://www.geeksforgeeks.org/linux-unix/bash-scripting-introduction-to-bash-and-bash-scripting/](https://www.geeksforgeeks.org/linux-unix/bash-scripting-introduction-to-bash-and-bash-scripting/)" %\}
