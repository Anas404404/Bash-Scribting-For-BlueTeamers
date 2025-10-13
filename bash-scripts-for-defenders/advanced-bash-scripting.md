# Advanced Bash Scripting

<figure><img src="https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/4134534_c110_7.jpg" alt=""><figcaption></figcaption></figure>

***

### Readings Arguments

arguments are the values given to the command line at the time a command or a Bash script is run. Bash enumerates these arguments like \`$1\`, \`$2\`, \`$3\`, etc. and makes them accessible.

* \`$0\`: Represents the name of the command or script.
* \`$1\`, \`$2\`, \`$3\`,...: these are used to access the first second, third, etc. arguments on the command line.
* \`$@\`: Represents all command line arguments as an array.
* \`$#\`: Represents the total number of arguments given on the command line.
* \`$\*\`: Represents all command line arguments as an array, but the arguments are concatenated into a single string.
* \`$?\`: Represents the exit status of the last command executed

For example, we can print a message using command line arguments in the following script:

```
#!/bin/bash

echo "Arguments from command line:"
echo "Argument 1: $1"
echo "Argument 2: $2"
echo "Argument 3: $3"
echo "All Arguments: $@"
echo "Total Arguments Count: $#"
```

To run this script, you can provide arguments on the command line like this:

```
./arguments.sh Hello World!
```

<figure><img src="https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash22.png" alt=""><figcaption></figcaption></figure>

#### shift



used to shift command line arguments and change access. Each shift command causes command line arguments to shift to the next position

```
#!/bin/bash

echo "Arguments from command line:"
echo "Argument 1: $1"

shift

echo "After shifting"
echo "Argument 1: $1"
```

<figure><img src="https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash23.png" alt=""><figcaption></figcaption></figure>

#### Getopts



getopts is a structure used in bash script to parse command line arguments and catch certain flags or options. It is often used with a “while” loop. With getopts you can add certain flags or options to your script and have the user use those flags or options in a certain way.

```
#!/bin/bash

while getopts ":a:bc" opt; do
  case ${opt} in
    a)
      echo "Option a is passed with value: $OPTARG"
      ;;
    b)
      echo "Option b is passed"
      ;;
    c)
      echo "Option c is passed"
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      ;;
  esac
done          
```

In this example, we are checking three separate options using the -a, -b, and -c flags.

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash24.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash24.png)

In the example below, the user is allowed to use either "-o" or "--option" options.\
This is a usage that provides comfort to the user when too many arguments are used.

```
#!/bin/bash

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -o|--option)
            option_value="$2"
            echo "Option value: $option_value"
            shift 2
            ;;
        *)
            echo "Invalid Argument: $1"
            exit 1
            ;;
    esac
    shift
done
```

**Shell Expansion**



property used to expand or evaluate special characters or expressions in a string. Expansion is performed immediately after a string on the command line, allowing the string to be replaced with a new value or otherwise manipulated

Bash shell expansion supports the following special characters or expressions :

* **Tilde expansion**\
  (\~): The tilde character represents a user's home directory (\`$HOME\`). For example, we can combine \`\~\` with \`\~/Documents\` to represent the user's "Documents" directory.
* **Parameter expansion**\
  ($): The \`$\` character represents the value of a variable. For example, we can get the user's home directory using \`$HOME\`.
* **Arithmetic expansion**\
  (()): The expression \`(( ))\` is used to evaluate arithmetic expressions. For example, the expression \`(( x = 5 + 3 ))\` assigns the value 5 + 3 to the variable \`x\`.
* **Conditional Expression Expansion**\
  The \`(( ))\` expression is used to evaluate conditional expressions. For example, with the expression \`(( x > y ))\` we can check whether the value \`x\` is greater than \`y\`.
* **Brace Expansion**\
  (${ }): The \`${ }\` expression is used to retrieve or manipulate the values of variables or string expressions. For example, with \`${var}\` we can get the value of the variable \`var\`.
* **Command Substitution**\
  (\` \` or ( ) ) : C o m m a n d s u b s t i t u t i o n i s u s e d t o o u t p u t a c o m m a n d a n d c a n b e p e r f o r m e d i n t w o d i f f e r e n t w a y s b y u s i n g b a c k q u o t e s ( ‘ ‘ ) o r ‘ ()\`. For example, with the expression \`result=$(date)\` we can assign the output of the \`date\` command to the \`result\` variable.
* **Arrays Expansion**\
  (${\[ ]}): The \`${\[ ]}\` expression is used to access the elements of arrays or perform operations related to the array. For example, we can access the first element of an array with the expression \`${array\[0]}\`.

```
#!/bin/bash

# Tilde Expansion (~)
echo "Home Directory: $HOME"
echo "Documents Directory: ~/Documents"

# Parameter Expansion ($)
greeting="Hello, World!"
echo "Greeting: $greeting"

# Arithmetic Expansion (())
(( x = 5 + 3 ))
echo "x = $x"

# Conditional Expression Expansion (())
x=10
y=5
if (( x > y )); then
  echo "x is greater than y"
else
  echo "x is not greater than y"
fi

# Brace Expansion (${ })
name="John"
echo "Hello, ${name}!"

# Command Substitution (` ` or $( ))
current_date=$(date)
echo "Current Date: $current_date"

# Array Expansion (${[ ]})
numbers=(10 20 30 40 50)
echo "First Number: ${numbers[0]}"
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash25.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash25.png)

When bash receives a command that a user types on the keyboard or comes from a bash script, it splits it into words. In doing so, Bash can perform seven different operations on words, which can change how they are interpreted and thus the output. There are 7 different expansions that we can use in Bash. Now let's examine them one by one:

*   #### <sub>Brace Expansion</sub> <sub>:</sub>



#### <sub>race Expansion is often used to create variations of a particular pattern in Bash : This command creates five different files named file\_1.txt, file\_2.txt, file\_3.txt, file\_4.txt and file\_5.txt.</sub>



```
touch file_{1..5}.txt
```

Also, this can be useful if a command is run repeatedly with different parameters.\
This script checks whether the files named "file1.txt", "file2.txt" and "file3.txt" are readable

```
#!/bin/bash
for i in {1..3}; do
    if [[ -r "file${i}.txt" ]]; then
        echo "You have read permission for file${i}.txt"
    else
        echo "You do not have read permission for file${i}.txt"
    fi
done
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash35.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash35.png)

*   #### Tilde Expansion



-a tilde expansion is actually replacing a path that points to a user's home directory.\
\- instead of taking risks by expressing the directory of a user whose name we know as /home/\<username>/ we can express it as **\~\<username>** .

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/shell-table.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/shell-table.png)

```
#!/bin/bash
echo ~
echo ~root
echo ~/Documents
echo ~root/Documents
echo ~+
echo ~-               
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash37.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash37.png)

*   #### Parameter and Variable Expansion



used to get the value of a variable. This variable can be a variable that we define in the script, or it can be a parameter that we give from the command line when calling our script

**Default Values:** If a variable is not defined, a default value can be assigned during expansion. We can use it as **${var:-default\_value}.**\
In this example, if the variable **name** is not defined, it will output "Unknown".

```
#!/bin/bash
echo ${name:-"Unknown"}
```

**Error Checking:** If the **${var:?error\_message}** form is used and if the variable is not defined, it will generate an error message and stop the script.

```
#!/bin/bash
echo ${name:?"Name is not set."}
```

**Substring Replacement: ${var/find/replace}** usage replaces the “ **find** ” expression in the “ **var** ” variable with “ **replace** ”. " **Hello, Earth!** " output after you run the script.

```
#!/bin/bash
greeting="Hello, World!"
echo ${greeting/World/Earth} 
```

we can treat all parameters as an array. And, we can do it by using @ o r \* expression.

```
#!/bin/bash

for prms in "$@"
do
  echo "Parameter: $prms"
done
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash38.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash38.png)

Using the IFS variable, you can split a string in bash by a specific character or string of characters. For example, you can set the IFS variable to a comma to split a comma-separated array:

```
#!/bin/bash

my_string="LetsDefend is ,one of the ,best resources on cybersecurity"

IFS=','
for word in $my_string
do
  echo $word
done
             
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash40.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash40.png)

#### Command Substitution



Every time you run this script, the “ **now** “ variable will be created with the current date and will produce a different output each time.

```
#!/bin/bash

now=$(date)
echo "The current date and time is: $now"
```

we do not define any variables and we output the ls command and use it at runtime.

```
#!/bin/bash

echo "Directory contents: $(ls)"
```

we can use them together : we list the disk space used by the files in our current directory.

```
#!/bin/bash

echo "File sizes: $(du -h $(pwd))"
```

#### Arithmetic Expansion



```
#!/bin/bash

echo $((5 + 2)) # Output: 7
echo $((5*2)) # Output: 10
echo $((10 / 2)) # Output: 5
echo $((10 - 5)) # Output: 5


num1=15
num2=5
echo $((num1 / num2)) # Output: 3
```

#### Word Splitting



process of converting a string into multiple values by splitting it according to a certain separator. It is often used when looping over an array or when you want to split the output of a command into multiple values.

```
#!/bin/bash

my_string="LetsDefend is one of the best resources on cybersecurity"

for word in $my_string
do
  echo $word
done
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash39.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash39.png)

how bash handles quotes. Word splitting does not occur when a string is in double quotes.\
example

```
#!/bin/bash

my_string="LetsDefend is one of the best resources on cybersecurity"

for word in “$my_string”
do
  echo $word
done
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash-split.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash-split.png)

**Pathname Expansion**



Bash uses various special characters and structures for pathname expansion:

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/shell-exp-t.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/shell-exp-t.png)

```
#!/bin/bash

# It lists all txt files.
ls *.txt

# Lists all files with a single character name.
ls ?

# List all files with a, b or c in their name.
ls *[abc]*

# Lists all files whose names match a given number range (1-3).
ls *[1-3]*
```

,shows the **.log** files under the **/var/log/** directory and how many lines of data are in them.

```
#!/bin/bash


dir_path="/var/log"

for file in $dir_path/*.log
do
  line_count=$(wc -l <"$file")
  echo "$file file has $line_count line log"
done
```

***

**RegEx and Bash**



* RegEx is a set of languages and techniques used to identify specific patterns in text and perform operations such as searching, matching and replacing according to these patterns.

For example, you can check if a particular word occurs in the text.

```
#!/bin/bash

# Check if a string matches a pattern
string="Hello, World!"
pattern="^Hello"

if [[ $string =~ $pattern ]]; then
    echo "Pattern matched!"
else
    echo "Pattern not matched!"
fi
```

For example, removing parameters from a URL or removing spaces in text

```
#!/bin/bash

# Replace occurrences of a word in a string
string="I love cats. Cats are amazing."
pattern="cats"
replacement="dogs"

new_string="${string//$pattern/$replacement}"
echo "New string: $new_string"      
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash30.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash30.png)

For example, checking the validity of an email address or verifying the accuracy of a phone number

```
#!/bin/bash

# Function to validate email address using RegEx
validateEmail() {
    email=$1
    pattern="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if [[ $email =~ $pattern ]]; then
        echo "Email address is valid."
    else
        echo "Email address is invalid."
    fi
}

# Prompt user to enter an email address
echo "Enter an email address:"
read user_email

# Call the validateEmail function with the entered email address
validateEmail "$user_email"
             
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash31.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash31.png)

For example, let's have an "access.log" file of a web server like the one below:

```
127.0.0.1 - - [28/May/2023:12:34:56 +0000] "GET /sayfa1 HTTP/1.1" 200 1234 "https://www.example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
127.0.0.1 - - [28/May/2023:12:34:57 +0000] "GET /sayfa2 HTTP/1.1" 200 5678 "https://www.example.com" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
...
```

we want to see the "User Agent" strings in this file in bulk:

```
#!/bin/bash

log_file="access.log"

# Check if log file exists
if [ ! -f "$log_file" ]; then
    echo "Log file $log_file not found."
    exit 1
fi

# Function to extract user agents from log file
extractUserAgents() {
    while IFS= read -r line; do
        user_agent=$(echo "$line" | awk -F'"' '{print $6}')
        echo "User Agent: $user_agent"
    done < "$log_file"
}

# Call the extractUserAgents function
extractUserAgents
```

<figure><img src="https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash32.png" alt=""><figcaption></figcaption></figure>

we want to find e-mail addresses in a text file, check for validity and generate a report

```
#!/bin/bash

input_file="input_file.txt"
output_file="report.txt"

# Check if input file exists
if [ ! -f "$input_file" ]; then
    echo "Input file $input_file not found."
    exit 1
fi

# Function to validate email address
validateEmail() {
    email=$1
    pattern="^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})$"

    if [[ $email =~ $pattern ]]; then
        echo "Valid Email: $email"
    else
        echo "Invalid Email: $email"
    fi
}

# Process input file and generate report
processFile() {
    while IFS= read -r line; do
        # Find email addresses using regex
        email_regex="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails=$(echo "$line" | grep -E -o "$email_regex")

        # Validate and write emails to output file
        for email in $emails; do
            validateEmail "$email" >> "$output_file"
        done
    done < "$input_file"

    echo "Report generated: $output_file"
}

# Call the processFile function
processFile
```

[![](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/raw/main2/.gitbook/assets/bash33.png)](https://github.com/Anas404404/Bash-Scribting-For-BlueTeamers/blob/main2/.gitbook/assets/bash33.png)
