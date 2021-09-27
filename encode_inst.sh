
# Use single quotes as argument:
# ./encode_inst.sh 'ADD edx, 42'

echo "    $@" > instruction.S
gcc -m32 -c ./single_inst.S
objdump -M intel -d ./single_inst.o | awk '/ <test>:$/ {seen = 1}; seen {print}'
rm ./single_inst.o
rm ./instruction.S
