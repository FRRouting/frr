# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  Bruno Bernard for NetDEF, Inc.

"""
ExaBGP Modifiers for topotato tests
"""

import logging
import os
from pathlib import Path
import tempfile
import time

from jinja2 import Environment


from topotato.assertions import TopotatoModifier
from topotato.base import skiptrace
from topotato.toponom import Router


jenv = Environment(
    line_comment_prefix="#" + "#",
    line_statement_prefix="#" + "%",
    autoescape=False,
)


class ExaBGP:
    """
    ExaBGP for controlling BGP

    >>> self.peer = ExaBGP(r1, configuration, custom_environment)
    >>> self.peer.start()
    >>> # control with cli
    >>> yield from peer.execute("neighbor 1.1.1.1 announce route 2001:db8::1/128 next-hop 2001:db8::2")
    >>> yield from peer.execute("neighbor 1.1.1.1 announce route 2001:db8::1/128 next-hop 2001:db8::2")
    >>> yield from self.peer.stop()
    """

    def __init__(self, rtr: Router, conf: str, custom_environment: str = None):
        self._all_routers = rtr.network.routers
        self._rtr = rtr
        self._conf = conf
        self._env = custom_environment

    class Action(TopotatoModifier):
        _rtr: str
        _cmdobj: "ExaBGP"

        # pylint: disable=arguments-differ,protected-access
        @classmethod
        def from_parent(cls, parent, name, cmdobj):
            name = f"{name}:{cmdobj._rtr.name} {cmdobj.__class__.__name__} ({cls.__name__})"
            self = super().from_parent(parent, name=name)

            self._rtr = cmdobj._rtr
            self._cmdobj = cmdobj
            return self

        def is_cli_ok(self):
            self._cmdobj.proc_cli.communicate()

            if self._cmdobj.proc_cli.returncode != 0:
                raise ValueError(
                    "nonzero exit: %s on cli" % self._cmdobj.proc_cli.returncode
                )

        def is_bgp_daemon_running(self):
            response = self._cmdobj.proc.poll()

            if response is not None:
                raise ValueError("exabgp is not running!")

    class Start(Action):
        # pylint: disable=consider-using-with
        def __call__(self):
            self._cmdobj.path = self.prepare_files()
            self.run()

        def prepare_files(self):
            timestr = time.strftime("%Y%m%d-%H%M%S")
            tempdir = tempfile.mkdtemp(prefix=f"exabgp-{timestr}-")
            cli_dir = os.path.join(tempdir, "run")
            logging.debug("exabgp tempfiles generated at %s", tempdir)

            def create_exabgp_folders():
                Path(cli_dir).mkdir(parents=True, exist_ok=True)

            def create_cli_files():
                exabgp_cli_file_path = os.path.join(cli_dir, "exabgp")

                os.mkfifo(f"{exabgp_cli_file_path}.in", mode=0o600)
                os.mkfifo(f"{exabgp_cli_file_path}.out", mode=0o600)

            def create_env():
                env_dir = os.path.join(tempdir, "exabgp.env")

                if self._cmdobj._env is not None:

                    with open(env_dir, "w", encoding="UTF-8") as env_file:
                        env_file.write(self._cmdobj._env)

                    return

                script_path = Path(__file__).resolve().parent

                template_dir = os.path.join(
                    script_path, "template", "exabgp.env.jinja2"
                )

                with open(template_dir, "r", encoding="UTF-8") as template_env, open(
                    env_dir, "w", encoding="UTF-8"
                ) as env_file:
                    template = jenv.from_string(template_env.read())
                    env = template.render(
                        {"log_destination": os.path.join(tempdir, "exabgp.log")}
                    )

                    env_file.write(env)

            def create_config():

                template = jenv.from_string(self._cmdobj._conf)

                conf = template.render({"routers": self._cmdobj._all_routers})

                conf_dir = os.path.join(tempdir, "conf.ini")

                with open(conf_dir, "w", encoding="UTF-8") as env_file:
                    env_file.writelines(conf)

            create_exabgp_folders()
            create_cli_files()
            create_env()
            create_config()

            return tempdir

        def run(self):
            router = self.instance.routers[self._rtr.name]
            path = self._cmdobj.path
            self._cmdobj.proc = router.popen(
                [
                    "exabgp",
                    "--debug",
                    os.path.join(path, "conf.ini"),
                    "--root",
                    path,
                    "--env",
                    os.path.join(path, "exabgp.env"),
                ],
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            )

            self.is_bgp_daemon_running()

    class Execute(Action):
        # pylint: disable=consider-using-with
        def __call__(self):

            self.is_bgp_daemon_running()

            router = self.instance.routers[self._rtr.name]
            path = self._cmdobj.path

            self._cmdobj.proc_cli = router.popen(
                ["exabgpcli", "--root", path, self._cmdobj._cmd],
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            )

            self.is_cli_ok()

    class Stop(Action):
        def __call__(self):

            self.is_bgp_daemon_running()

            router = self.instance.routers[self._rtr.name]

            path = self._cmdobj.path
            self._cmdobj.proc_cli = router.popen(
                ["exabgpcli", "--root", path, "shutdown"],
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            )

            self.is_cli_ok()

    @skiptrace
    def start(self):
        yield from self.Start.make(self)

    @skiptrace
    def execute(self, cmd):
        self._cmd = cmd
        yield from self.Execute.make(self)

    @skiptrace
    def stop(self):
        yield from self.Stop.make(self)
