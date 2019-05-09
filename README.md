# ipm
Remote IP management module provide a mechanism to detect connectivity status between Host nodes and the ATCAv2 Shelf Management Controller (ShMC).
##
It maintains the route table by deletiing the bad route path and adding the good route path to guarantee the current route path in use works well. In some conditions, ShMC will be requested to switched over.