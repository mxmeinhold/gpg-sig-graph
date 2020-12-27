import argparse

from . import main

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Graph signatures between gpg keys',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-f', '--file', required=False, dest='file_name',
            help='Write to a given file rather than stdout')

    args = parser.parse_args()

    if args.file_name:
        with open(args.file_name, 'w') as args.out_file:
            main(**args.__dict__)
    else:
        main(**args.__dict__)
