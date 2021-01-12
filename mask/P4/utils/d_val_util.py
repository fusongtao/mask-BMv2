#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import json
import logging


class DVal(object):
    d_val = None

    @classmethod
    def setDVal(cls, new_d_val):
        cls.d_val = new_d_val

    @classmethod
    def setDValItem(cls, name, ip, value):
        if cls.d_val.get(name) is None:
            cls.d_val[name] = {}
        cls.d_val[name][ip] = value

    @classmethod
    def getDVal(cls, filepath='../assets/dval.json'):
        if cls.d_val:
            return cls.d_val
        else:
            return cls.getFromFile(filepath)

    @classmethod
    def writeToFile(cls, filepath='../assets/dval.json'):
        with open(filepath, 'w') as f:
            f.write(json.dumps(cls.d_val))
            logging.info("Write to filename: %s " % filepath)

    @classmethod
    def getFromFile(cls, filepath='../assets/dval.json'):
        with open(filepath, 'r') as f:
            json_str = f.read()
            cls.d_val = json.loads(json_str)
            logging.info(("got from filename: ", cls.d_val))
        return cls.d_val
