Testing:

For testing, I ran various tests for the inputs listed in my rules.csv file. I primarily tested edge cases
for example if an input had a range value for both IP-address and port number, I tested a minimum edge case 
which comprised of both the min value for ip address and port number in a range. I tested the maximum values in the ranges
as well, and in addition to that, I tested a values in the middle of both ranges. I conducted similar tests
for values with ranges in IP-address but no ranges in port number and vice versa.

Implementation: 

There were many implementation decisions I considered when designing the firewall. For storage purposes, I decided to use a python list to store tuples of network rules. This would result in O(n) run time when searching 
for matches between the incoming packet data and network rules. I also considered the fastest ways to compute and add all
possible combinations of values in the ranges of IP-address and port number inputs. For the most part I was able to accomplish this
in O(n) run time however for values with both ranges in IP-address and port number I had to implement the adding operation in O(n^2)
run time. I considered the fastest possible runtime when dealing with searches in individual tuples by using a python dictionary.
This resulted in O(1) run time. I considered space complexity as well during my design and 
implementation regarding storing the rules.I was able to implement the list in O(n) workspace units which is equivalent to creating a rule for every tuple in 
ranges of IP-address’ and port numbers.

Extra time/Refinements:

If I had more than 60-90 minutes, I would have used a hash table which is represented by a python dictionary to increase the
run time efficiency of the accept function to O(1) run time. I would have implemented a hash function using all values in the
network rules tuples and mapped the function's return value to a bucket in the dictionary. The search operation would then be a check if a particular
packet mapped to an existing value in the dictionary. In terms of optimizing the space complexity I would have looked into creating a function
to check(when the file is being parsed) if a particular packets IP-address/port number falls within the input ranges, instead of adding all possible input 
range combinations. This would significantly reduce the space complexity.

Extra Info:

Used python 2.7 and the built in csv library

Teams:

I am strongly interested in the Platform team but am open and interested in all teams.
