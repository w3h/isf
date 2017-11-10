import sys,os

ppp = os.path.split(os.path.realpath(__file__))[0]
sys.path.append(ppp)
sys.path.append(ppp + '/thirdparty')
sys.path.append(ppp + '/protocols')
