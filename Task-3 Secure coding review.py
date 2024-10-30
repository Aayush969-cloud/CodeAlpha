print("Welcome to the Calculator! 😊")

# Define functions for operations


def add(x, y):
    return x + y


def sub(x, y):
    return x - y


def mul(x, y):
    return x * y


def div(x, y):
    # Handle division by zero
    if y == 0:
        return "Error! Division by zero."
    return x / y


# Display options to the user
print("1: Addition \n2: Subtraction \n3: Multiplication \n4: Division")
user_choice = int(input("Enter your choice (1/2/3/4): "))

# Get input numbers
num1 = float(input("Enter first number: "))
num2 = float(input("Enter second number: "))

# Perform the selected operation
if user_choice == 1:
    print(f"{num1} + {num2} = {add(num1, num2)}")
elif user_choice == 2:
    print(f"{num1} - {num2} = {sub(num1, num2)}")
elif user_choice == 3:
    print(f"{num1} * {num2} = {mul(num1, num2)}")
elif user_choice == 4:
    print(f"{num1} / {num2} = {div(num1, num2)}")
else:
    print("Invalid input")

print("Thanks😊")
