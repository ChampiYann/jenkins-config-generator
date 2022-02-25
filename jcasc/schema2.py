from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any, List, TypeVar, Type, cast, Callable

from jcasc.schema import Jobs

T = TypeVar("T")
EnumT = TypeVar("EnumT", bound=Enum)


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


class Deprecated(Enum):
    REJECT = "reject"
    WARN = "warn"


class Restricted(Enum):
    BETA = "beta"
    REJECT = "reject"
    WARN = "warn"


class Version(Enum):
    THE_1 = "1"

@dataclass
class Job:
    script: Optional[str] = None
    file: Optional[str] = None
    url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Jobs':
        assert isinstance(obj, dict)
        script = from_union([from_str, from_none], obj.get("script"))
        file = from_union([from_str, from_none], obj.get("file"))
        url = from_union([from_str, from_none], obj.get("url"))
        return Jobs()

    def to_dict(self) -> dict:
        result: dict = {}
        result["script"] = from_union([from_str, from_none], self.script)
        result["file"] = from_union([from_str, from_none], self.file)
        result["url"] = from_union([from_str, from_none], self.url)
        return result

@dataclass
class Coordinate:
    """Jenkins Configuration as Code"""
    # configuration_as_code: Optional[ConfigurationBaseForTheConfigurationAsCodeClassifier] = None
    # credentials: Optional[ConfigurationBaseForTheCredentialsClassifier] = None
    # global_credentials_configuration: Optional[ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier] = None
    # jenkins: Optional[ConfigurationBaseForTheJenkinsClassifier] = None
    jobs: Optional[List[Job]] = None
    # security: Optional[ConfigurationBaseForTheSecurityClassifier] = None
    # tool: Optional[ConfigurationBaseForTheToolClassifier] = None
    # unclassified: Optional[ConfigurationBaseForTheUnclassifiedClassifier] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Coordinate':
        assert isinstance(obj, dict)
        # configuration_as_code = from_union([ConfigurationBaseForTheConfigurationAsCodeClassifier.from_dict, from_none], obj.get("configuration-as-code"))
        # credentials = from_union([ConfigurationBaseForTheCredentialsClassifier.from_dict, from_none], obj.get("credentials"))
        # global_credentials_configuration = from_union([ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier.from_dict, from_none], obj.get("globalCredentialsConfiguration"))
        # jenkins = from_union([ConfigurationBaseForTheJenkinsClassifier.from_dict, from_none], obj.get("jenkins"))
        jobs = from_union([lambda x: from_list(Job.from_dict, x), from_none], obj.get("jobs"))
        # security = from_union([ConfigurationBaseForTheSecurityClassifier.from_dict, from_none], obj.get("security"))
        # tool = from_union([ConfigurationBaseForTheToolClassifier.from_dict, from_none], obj.get("tool"))
        # unclassified = from_union([ConfigurationBaseForTheUnclassifiedClassifier.from_dict, from_none], obj.get("unclassified"))
        return Coordinate(configuration_as_code, credentials, global_credentials_configuration, jenkins, jobs, security, tool, unclassified)

    def to_dict(self) -> dict:
        result: dict = {}
        # result["configuration-as-code"] = from_union([lambda x: to_class(ConfigurationBaseForTheConfigurationAsCodeClassifier, x), from_none], self.configuration_as_code)
        # result["credentials"] = from_union([lambda x: to_class(ConfigurationBaseForTheCredentialsClassifier, x), from_none], self.credentials)
        # result["globalCredentialsConfiguration"] = from_union([lambda x: to_class(ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier, x), from_none], self.global_credentials_configuration)
        # result["jenkins"] = from_union([lambda x: to_class(ConfigurationBaseForTheJenkinsClassifier, x), from_none], self.jenkins)
        result["jobs"] = from_union([lambda x: from_list(lambda x: to_class(Job, x), x), from_none], self.jobs)
        # result["security"] = from_union([lambda x: to_class(ConfigurationBaseForTheSecurityClassifier, x), from_none], self.security)
        # result["tool"] = from_union([lambda x: to_class(ConfigurationBaseForTheToolClassifier, x), from_none], self.tool)
        # result["unclassified"] = from_union([lambda x: to_class(ConfigurationBaseForTheUnclassifiedClassifier, x), from_none], self.unclassified)
        return result

def coordinate_from_dict(s: Any) -> Coordinate:
    return Coordinate.from_dict(s)


def coordinate_to_dict(x: Coordinate) -> Any:
    return to_class(Coordinate, x)
