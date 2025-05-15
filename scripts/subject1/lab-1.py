# -*- coding: utf-8 -*-

import sys
import random

def run_tests(lab_id):
    print("Running tests for lab ID: {}".format(lab_id))
    if random.choice([True, False]):
        print("Тест пройден.")
    else:
        print("Тест не пройден.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python lab-1.py <lab_id>")
        sys.exit(1)
    lab_id = sys.argv[1]
    run_tests(lab_id)