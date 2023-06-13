v   := vagrant
vu  := $(v) up
vh := $(v) halt
vr := $(v) reload
vs := $(v) ssh
vsc := $(vs) -c
t := ./run_userns.sh --frr-builddir=/home/vagrant/frr --log-cli-level=DEBUG -v -v -x
cwd := cd /home/vagrant/dev/topotato
build:
	$(vu) --provision

reload:
	$(vr)
	$(vs)

start:
	$(vu)

bash:
	$(vs) -c '$(cwd) && bash'

exec:
	$(vs) -c '$(filter-out $@,$(MAKECMDGOALS))'

run:
	$(vs) -c '$(cwd) && $(t) $(filter-out $@,$(MAKECMDGOALS))'


%:
	@:
