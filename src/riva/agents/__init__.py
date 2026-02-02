"""Agent detection modules.

Public API for extending Riva with new agent support:

    from riva.agents import AgentDetector, SimpleAgentDetector, register_agent

Five ways to add a new agent:

1. **SimpleAgentDetector** — data-driven, zero subclassing::

       from riva.agents import SimpleAgentDetector
       detector = SimpleAgentDetector(
           name="My Agent", binaries=["myagent"],
           config="~/.myagent", api="api.example.com",
       )

2. **Subclass AgentDetector** — for custom process matching / config parsing.

3. **@register_agent decorator** — auto-registered when the module is imported::

       @register_agent
       class MyDetector(AgentDetector): ...

4. **entry_points** — third-party pip packages::

       # pyproject.toml
       [project.entry-points."riva.agents"]
       my_agent = "my_package:create_detector"

5. **Plugin directory** — drop a .py file into ~/.config/riva/plugins/
   with a ``create_detector()`` function.
"""

from riva.agents.base import (
    AgentDetector,
    AgentInstance,
    AgentStatus,
    SimpleAgentDetector,
    filter_secrets,
)
from riva.agents.registry import AgentRegistry, get_default_registry, register_agent

__all__ = [
    "AgentDetector",
    "AgentInstance",
    "AgentRegistry",
    "AgentStatus",
    "SimpleAgentDetector",
    "filter_secrets",
    "get_default_registry",
    "register_agent",
]
