import argparse

parser = argparse.ArgumentParser()

parser.add_argument('message')
parser.add_argument('-n', nargs=2, type = float)

args = parser.parse_args()

print(args)
print(args.n[1])
print(args.message )