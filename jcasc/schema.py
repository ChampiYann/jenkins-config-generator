# To use this code, make sure you
#
#     import json
#
# and then, to convert JSON from a string, do
#
#     result = coordinate_from_dict(json.loads(json_string))

from enum import Enum
from dataclasses import dataclass
from typing import Optional, Any, List, TypeVar, Type, cast, Callable


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
class ConfigurationBaseForTheConfigurationAsCodeClassifier:
    deprecated: Optional[Deprecated] = None
    restricted: Optional[Restricted] = None
    unknown: Optional[Deprecated] = None
    version: Optional[Version] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ConfigurationBaseForTheConfigurationAsCodeClassifier':
        assert isinstance(obj, dict)
        deprecated = from_union([Deprecated, from_none], obj.get("deprecated"))
        restricted = from_union([Restricted, from_none], obj.get("restricted"))
        unknown = from_union([Deprecated, from_none], obj.get("unknown"))
        version = from_union([Version, from_none], obj.get("version"))
        return ConfigurationBaseForTheConfigurationAsCodeClassifier(deprecated, restricted, unknown, version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["deprecated"] = from_union([lambda x: to_enum(Deprecated, x), from_none], self.deprecated)
        result["restricted"] = from_union([lambda x: to_enum(Restricted, x), from_none], self.restricted)
        result["unknown"] = from_union([lambda x: to_enum(Deprecated, x), from_none], self.unknown)
        result["version"] = from_union([lambda x: to_enum(Version, x), from_none], self.version)
        return result


@dataclass
class PurplePrivateKeySource:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurplePrivateKeySource':
        assert isinstance(obj, dict)
        return PurplePrivateKeySource()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


class Scope(Enum):
    GLOBAL = "GLOBAL"
    SYSTEM = "SYSTEM"
    USER = "USER"


@dataclass
class CredentialsBasicSSHUserPrivateKey:
    description: Optional[str] = None
    id: Optional[str] = None
    passphrase: Optional[str] = None
    private_key_source: Optional[PurplePrivateKeySource] = None
    scope: Optional[Scope] = None
    username: Optional[str] = None
    """By default, usernames are not masked in the build log.
    You may choose to mask a credential's username if you consider it to be sensitive
    information.
    However, this can interfere with diagnostics.
    For example, if the username is a common word it will cause unrelated occurrences of that
    word to also be masked.
    
    Regardless of this setting, the username will be displayed in the selection dropdown to
    anyone permitted to reconfigure the credentials.
    """
    username_secret: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsBasicSSHUserPrivateKey':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        passphrase = from_union([from_str, from_none], obj.get("passphrase"))
        private_key_source = from_union([PurplePrivateKeySource.from_dict, from_none], obj.get("privateKeySource"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        username = from_union([from_str, from_none], obj.get("username"))
        username_secret = from_union([from_bool, from_none], obj.get("usernameSecret"))
        return CredentialsBasicSSHUserPrivateKey(description, id, passphrase, private_key_source, scope, username, username_secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["passphrase"] = from_union([from_str, from_none], self.passphrase)
        result["privateKeySource"] = from_union([lambda x: to_class(PurplePrivateKeySource, x), from_none], self.private_key_source)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        result["username"] = from_union([from_str, from_none], self.username)
        result["usernameSecret"] = from_union([from_bool, from_none], self.username_secret)
        return result


@dataclass
class PurpleKeyStoreSource:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The source of the certificate.
    """
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleKeyStoreSource':
        assert isinstance(obj, dict)
        return PurpleKeyStoreSource()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsCertificate:
    description: Optional[str] = None
    id: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The source of the certificate.
    """
    key_store_source: Optional[PurpleKeyStoreSource] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The password. The use of separate integrity and encryption passwords is not supported.
    """
    password: Optional[str] = None
    scope: Optional[Scope] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsCertificate':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        key_store_source = from_union([PurpleKeyStoreSource.from_dict, from_none], obj.get("keyStoreSource"))
        password = from_union([from_str, from_none], obj.get("password"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        return CredentialsCertificate(description, id, key_store_source, password, scope)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["keyStoreSource"] = from_union([lambda x: to_class(PurpleKeyStoreSource, x), from_none], self.key_store_source)
        result["password"] = from_union([from_str, from_none], self.password)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        return result


@dataclass
class CredentialsCredentials:
    file: Any
    string: Any
    basic_ssh_user_private_key: Any
    certificate: Any
    username_password: Any

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsCredentials':
        assert isinstance(obj, dict)
        file = obj.get("file")
        string = obj.get("string")
        basic_ssh_user_private_key = obj.get("basicSSHUserPrivateKey")
        certificate = obj.get("certificate")
        username_password = obj.get("usernamePassword")
        return CredentialsCredentials(file, string, basic_ssh_user_private_key, certificate, username_password)

    def to_dict(self) -> dict:
        result: dict = {}
        result["file"] = self.file
        result["string"] = self.string
        result["basicSSHUserPrivateKey"] = self.basic_ssh_user_private_key
        result["certificate"] = self.certificate
        result["usernamePassword"] = self.username_password
        return result


@dataclass
class PurplePrivateKey:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurplePrivateKey':
        assert isinstance(obj, dict)
        return PurplePrivateKey()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsDirectEntry:
    private_key: Optional[PurplePrivateKey] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsDirectEntry':
        assert isinstance(obj, dict)
        private_key = from_union([PurplePrivateKey.from_dict, from_none], obj.get("privateKey"))
        return CredentialsDirectEntry(private_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["privateKey"] = from_union([lambda x: to_class(PurplePrivateKey, x), from_none], self.private_key)
        return result


@dataclass
class PurpleSpecification:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleSpecification':
        assert isinstance(obj, dict)
        return PurpleSpecification()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsDomain:
    description: Optional[str] = None
    name: Optional[str] = None
    specifications: Optional[List[PurpleSpecification]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsDomain':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        name = from_union([from_str, from_none], obj.get("name"))
        specifications = from_union([lambda x: from_list(PurpleSpecification.from_dict, x), from_none], obj.get("specifications"))
        return CredentialsDomain(description, name, specifications)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["name"] = from_union([from_str, from_none], self.name)
        result["specifications"] = from_union([lambda x: from_list(lambda x: to_class(PurpleSpecification, x), x), from_none], self.specifications)
        return result


@dataclass
class PurpleCredential:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleCredential':
        assert isinstance(obj, dict)
        return PurpleCredential()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleDomain:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleDomain':
        assert isinstance(obj, dict)
        return PurpleDomain()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsDomainCredentials:
    credentials: Optional[List[PurpleCredential]] = None
    domain: Optional[PurpleDomain] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsDomainCredentials':
        assert isinstance(obj, dict)
        credentials = from_union([lambda x: from_list(PurpleCredential.from_dict, x), from_none], obj.get("credentials"))
        domain = from_union([PurpleDomain.from_dict, from_none], obj.get("domain"))
        return CredentialsDomainCredentials(credentials, domain)

    def to_dict(self) -> dict:
        result: dict = {}
        result["credentials"] = from_union([lambda x: from_list(lambda x: to_class(PurpleCredential, x), x), from_none], self.credentials)
        result["domain"] = from_union([lambda x: to_class(PurpleDomain, x), from_none], self.domain)
        return result


@dataclass
class CredentialsDomainSpecification:
    scheme_specification: Any
    hostname_port_specification: Any
    path_specification: Any
    hostname_specification: Any

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsDomainSpecification':
        assert isinstance(obj, dict)
        scheme_specification = obj.get("schemeSpecification")
        hostname_port_specification = obj.get("hostnamePortSpecification")
        path_specification = obj.get("pathSpecification")
        hostname_specification = obj.get("hostnameSpecification")
        return CredentialsDomainSpecification(scheme_specification, hostname_port_specification, path_specification, hostname_specification)

    def to_dict(self) -> dict:
        result: dict = {}
        result["schemeSpecification"] = self.scheme_specification
        result["hostnamePortSpecification"] = self.hostname_port_specification
        result["pathSpecification"] = self.path_specification
        result["hostnameSpecification"] = self.hostname_specification
        return result


@dataclass
class PurpleSecretBytes:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleSecretBytes':
        assert isinstance(obj, dict)
        return PurpleSecretBytes()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsFile:
    description: Optional[str] = None
    file_name: Optional[str] = None
    id: Optional[str] = None
    scope: Optional[Scope] = None
    secret_bytes: Optional[PurpleSecretBytes] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsFile':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        file_name = from_union([from_str, from_none], obj.get("fileName"))
        id = from_union([from_str, from_none], obj.get("id"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        secret_bytes = from_union([PurpleSecretBytes.from_dict, from_none], obj.get("secretBytes"))
        return CredentialsFile(description, file_name, id, scope, secret_bytes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["fileName"] = from_union([from_str, from_none], self.file_name)
        result["id"] = from_union([from_str, from_none], self.id)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        result["secretBytes"] = from_union([lambda x: to_class(PurpleSecretBytes, x), from_none], self.secret_bytes)
        return result


@dataclass
class Folder:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Folder':
        assert isinstance(obj, dict)
        return Folder()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FolderCredentialsProvider:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FolderCredentialsProvider':
        assert isinstance(obj, dict)
        return FolderCredentialsProvider()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsHostnamePortSpecification:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of excluded hostnames. (The * wildcard is permitted in
    hostnames,
    for example: jenkins-ci.org:*, *.jenkins-ci.org:80, jenkinsci.github.io:443.)
    
    The empty list implies no hostname:port is excluded. The excludes list is processed after
    the includes
    list.
    """
    excludes: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of included hostnames. (The * wildcard is permitted in
    hostnames,
    for example: jenkins-ci.org:*, *.jenkins-ci.org:80, jenkinsci.github.io:443.)
    
    The empty list implies no hostname:port is excluded. The excludes list is processed after
    the includes
    list.
    """
    includes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsHostnamePortSpecification':
        assert isinstance(obj, dict)
        excludes = from_union([from_str, from_none], obj.get("excludes"))
        includes = from_union([from_str, from_none], obj.get("includes"))
        return CredentialsHostnamePortSpecification(excludes, includes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludes"] = from_union([from_str, from_none], self.excludes)
        result["includes"] = from_union([from_str, from_none], self.includes)
        return result


@dataclass
class CredentialsHostnameSpecification:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of excluded hostnames. (The * wildcard is permitted in
    hostnames,
    for example: jenkins-ci.org, *.jenkins-ci.org, jenkinsci.github.io.)
    
    The empty list implies no hostnames are excluded. The excludes list is processed after
    the includes list.
    """
    excludes: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of included hostnames. (The * wildcard is permitted in
    hostnames,
    for example: jenkins-ci.org, *.jenkins-ci.org, jenkinsci.github.io.)
    
    The empty list implies no hostnames are excluded. The excludes list is processed after
    the includes list.
    """
    includes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsHostnameSpecification':
        assert isinstance(obj, dict)
        excludes = from_union([from_str, from_none], obj.get("excludes"))
        includes = from_union([from_str, from_none], obj.get("includes"))
        return CredentialsHostnameSpecification(excludes, includes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludes"] = from_union([from_str, from_none], self.excludes)
        result["includes"] = from_union([from_str, from_none], self.includes)
        return result


@dataclass
class CredentialsKeyStoreSource:
    uploaded: Any

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsKeyStoreSource':
        assert isinstance(obj, dict)
        uploaded = obj.get("uploaded")
        return CredentialsKeyStoreSource(uploaded)

    def to_dict(self) -> dict:
        result: dict = {}
        result["uploaded"] = self.uploaded
        return result


@dataclass
class CredentialsPathSpecification:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2014, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    Select this option to require that the paths match taking character case into account.
    """
    case_sensitive: Optional[bool] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2014, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of excluded paths. (ANT style * and ** wildcards are permitted in
    paths,
    for example: /jenkins/github/*,/jenkins-ci/**/org,jenkinsci.github.io.)
    
    The empty list implies no paths are excluded. The excludes list is processed after the
    includes list.
    """
    excludes: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2014, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of included paths. (ANT style * and ** wildcards are permitted in
    paths,
    for example: /jenkins/github/*,/jenkins-ci/**/org,jenkinsci.github.io.)
    
    The empty list implies no paths are excluded. The excludes list is processed after the
    includes list.
    """
    includes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsPathSpecification':
        assert isinstance(obj, dict)
        case_sensitive = from_union([from_bool, from_none], obj.get("caseSensitive"))
        excludes = from_union([from_str, from_none], obj.get("excludes"))
        includes = from_union([from_str, from_none], obj.get("includes"))
        return CredentialsPathSpecification(case_sensitive, excludes, includes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["caseSensitive"] = from_union([from_bool, from_none], self.case_sensitive)
        result["excludes"] = from_union([from_str, from_none], self.excludes)
        result["includes"] = from_union([from_str, from_none], self.includes)
        return result


@dataclass
class CredentialsPrivateKeySource:
    direct_entry: Any

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsPrivateKeySource':
        assert isinstance(obj, dict)
        direct_entry = obj.get("directEntry")
        return CredentialsPrivateKeySource(direct_entry)

    def to_dict(self) -> dict:
        result: dict = {}
        result["directEntry"] = self.direct_entry
        return result


@dataclass
class ProviderImpl:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ProviderImpl':
        assert isinstance(obj, dict)
        return ProviderImpl()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsSchemeSpecification:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of URI schemes (as defined in RFC-3986).
    For example: http, https, ssh, sftp, imap.
    """
    schemes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsSchemeSpecification':
        assert isinstance(obj, dict)
        schemes = from_union([from_str, from_none], obj.get("schemes"))
        return CredentialsSchemeSpecification(schemes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["schemes"] = from_union([from_str, from_none], self.schemes)
        return result


@dataclass
class PurpleSecret:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleSecret':
        assert isinstance(obj, dict)
        return PurpleSecret()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsString:
    description: Optional[str] = None
    id: Optional[str] = None
    scope: Optional[Scope] = None
    secret: Optional[PurpleSecret] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsString':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        secret = from_union([PurpleSecret.from_dict, from_none], obj.get("secret"))
        return CredentialsString(description, id, scope, secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        result["secret"] = from_union([lambda x: to_class(PurpleSecret, x), from_none], self.secret)
        return result


@dataclass
class System:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'System':
        assert isinstance(obj, dict)
        return System()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleUploadedKeystore:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleUploadedKeystore':
        assert isinstance(obj, dict)
        return PurpleUploadedKeystore()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsUploaded:
    uploaded_keystore: Optional[PurpleUploadedKeystore] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsUploaded':
        assert isinstance(obj, dict)
        uploaded_keystore = from_union([PurpleUploadedKeystore.from_dict, from_none], obj.get("uploadedKeystore"))
        return CredentialsUploaded(uploaded_keystore)

    def to_dict(self) -> dict:
        result: dict = {}
        result["uploadedKeystore"] = from_union([lambda x: to_class(PurpleUploadedKeystore, x), from_none], self.uploaded_keystore)
        return result


@dataclass
class CredentialsUser:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsUser':
        assert isinstance(obj, dict)
        return CredentialsUser()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UserCredentialsProvider:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UserCredentialsProvider':
        assert isinstance(obj, dict)
        return UserCredentialsProvider()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CredentialsUsernamePassword:
    description: Optional[str] = None
    id: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The password.
    """
    password: Optional[str] = None
    scope: Optional[Scope] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The username.
    """
    username: Optional[str] = None
    """Historically, not only passwords but usernames were masked in the build log.
    Since these can interfere with diagnostics,
    and cause unrelated occurrences of a common word to be masked,
    you may choose to leave usernames unmasked if they are not sensitive.
    Note that regardless of this setting, the username will be displayed to anyone permitted
    to reconfigure the credentials.
    """
    username_secret: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsUsernamePassword':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        password = from_union([from_str, from_none], obj.get("password"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        username = from_union([from_str, from_none], obj.get("username"))
        username_secret = from_union([from_bool, from_none], obj.get("usernameSecret"))
        return CredentialsUsernamePassword(description, id, password, scope, username, username_secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["password"] = from_union([from_str, from_none], self.password)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        result["username"] = from_union([from_str, from_none], self.username)
        result["usernameSecret"] = from_union([from_bool, from_none], self.username_secret)
        return result


@dataclass
class ConfigurationBaseForTheCredentialsClassifier:
    basic_ssh_user_private_key: Optional[CredentialsBasicSSHUserPrivateKey] = None
    certificate: Optional[CredentialsCertificate] = None
    credentials: Optional[CredentialsCredentials] = None
    direct_entry: Optional[CredentialsDirectEntry] = None
    domain: Optional[CredentialsDomain] = None
    domain_credentials: Optional[CredentialsDomainCredentials] = None
    domain_specification: Optional[CredentialsDomainSpecification] = None
    file: Optional[CredentialsFile] = None
    folder: Optional[Folder] = None
    folder_credentials_provider: Optional[FolderCredentialsProvider] = None
    hostname_port_specification: Optional[CredentialsHostnamePortSpecification] = None
    hostname_specification: Optional[CredentialsHostnameSpecification] = None
    key_store_source: Optional[CredentialsKeyStoreSource] = None
    path_specification: Optional[CredentialsPathSpecification] = None
    private_key_source: Optional[CredentialsPrivateKeySource] = None
    provider_impl: Optional[ProviderImpl] = None
    scheme_specification: Optional[CredentialsSchemeSpecification] = None
    string: Optional[CredentialsString] = None
    system: Optional[System] = None
    uploaded: Optional[CredentialsUploaded] = None
    user: Optional[CredentialsUser] = None
    user_credentials_provider: Optional[UserCredentialsProvider] = None
    username_password: Optional[CredentialsUsernamePassword] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ConfigurationBaseForTheCredentialsClassifier':
        assert isinstance(obj, dict)
        basic_ssh_user_private_key = from_union([CredentialsBasicSSHUserPrivateKey.from_dict, from_none], obj.get("basicSSHUserPrivateKey"))
        certificate = from_union([CredentialsCertificate.from_dict, from_none], obj.get("certificate"))
        credentials = from_union([CredentialsCredentials.from_dict, from_none], obj.get("credentials"))
        direct_entry = from_union([CredentialsDirectEntry.from_dict, from_none], obj.get("directEntry"))
        domain = from_union([CredentialsDomain.from_dict, from_none], obj.get("domain"))
        domain_credentials = from_union([CredentialsDomainCredentials.from_dict, from_none], obj.get("domainCredentials"))
        domain_specification = from_union([CredentialsDomainSpecification.from_dict, from_none], obj.get("domainSpecification"))
        file = from_union([CredentialsFile.from_dict, from_none], obj.get("file"))
        folder = from_union([Folder.from_dict, from_none], obj.get("folder"))
        folder_credentials_provider = from_union([FolderCredentialsProvider.from_dict, from_none], obj.get("folderCredentialsProvider"))
        hostname_port_specification = from_union([CredentialsHostnamePortSpecification.from_dict, from_none], obj.get("hostnamePortSpecification"))
        hostname_specification = from_union([CredentialsHostnameSpecification.from_dict, from_none], obj.get("hostnameSpecification"))
        key_store_source = from_union([CredentialsKeyStoreSource.from_dict, from_none], obj.get("keyStoreSource"))
        path_specification = from_union([CredentialsPathSpecification.from_dict, from_none], obj.get("pathSpecification"))
        private_key_source = from_union([CredentialsPrivateKeySource.from_dict, from_none], obj.get("privateKeySource"))
        provider_impl = from_union([ProviderImpl.from_dict, from_none], obj.get("providerImpl"))
        scheme_specification = from_union([CredentialsSchemeSpecification.from_dict, from_none], obj.get("schemeSpecification"))
        string = from_union([CredentialsString.from_dict, from_none], obj.get("string"))
        system = from_union([System.from_dict, from_none], obj.get("system"))
        uploaded = from_union([CredentialsUploaded.from_dict, from_none], obj.get("uploaded"))
        user = from_union([CredentialsUser.from_dict, from_none], obj.get("user"))
        user_credentials_provider = from_union([UserCredentialsProvider.from_dict, from_none], obj.get("userCredentialsProvider"))
        username_password = from_union([CredentialsUsernamePassword.from_dict, from_none], obj.get("usernamePassword"))
        return ConfigurationBaseForTheCredentialsClassifier(basic_ssh_user_private_key, certificate, credentials, direct_entry, domain, domain_credentials, domain_specification, file, folder, folder_credentials_provider, hostname_port_specification, hostname_specification, key_store_source, path_specification, private_key_source, provider_impl, scheme_specification, string, system, uploaded, user, user_credentials_provider, username_password)

    def to_dict(self) -> dict:
        result: dict = {}
        result["basicSSHUserPrivateKey"] = from_union([lambda x: to_class(CredentialsBasicSSHUserPrivateKey, x), from_none], self.basic_ssh_user_private_key)
        result["certificate"] = from_union([lambda x: to_class(CredentialsCertificate, x), from_none], self.certificate)
        result["credentials"] = from_union([lambda x: to_class(CredentialsCredentials, x), from_none], self.credentials)
        result["directEntry"] = from_union([lambda x: to_class(CredentialsDirectEntry, x), from_none], self.direct_entry)
        result["domain"] = from_union([lambda x: to_class(CredentialsDomain, x), from_none], self.domain)
        result["domainCredentials"] = from_union([lambda x: to_class(CredentialsDomainCredentials, x), from_none], self.domain_credentials)
        result["domainSpecification"] = from_union([lambda x: to_class(CredentialsDomainSpecification, x), from_none], self.domain_specification)
        result["file"] = from_union([lambda x: to_class(CredentialsFile, x), from_none], self.file)
        result["folder"] = from_union([lambda x: to_class(Folder, x), from_none], self.folder)
        result["folderCredentialsProvider"] = from_union([lambda x: to_class(FolderCredentialsProvider, x), from_none], self.folder_credentials_provider)
        result["hostnamePortSpecification"] = from_union([lambda x: to_class(CredentialsHostnamePortSpecification, x), from_none], self.hostname_port_specification)
        result["hostnameSpecification"] = from_union([lambda x: to_class(CredentialsHostnameSpecification, x), from_none], self.hostname_specification)
        result["keyStoreSource"] = from_union([lambda x: to_class(CredentialsKeyStoreSource, x), from_none], self.key_store_source)
        result["pathSpecification"] = from_union([lambda x: to_class(CredentialsPathSpecification, x), from_none], self.path_specification)
        result["privateKeySource"] = from_union([lambda x: to_class(CredentialsPrivateKeySource, x), from_none], self.private_key_source)
        result["providerImpl"] = from_union([lambda x: to_class(ProviderImpl, x), from_none], self.provider_impl)
        result["schemeSpecification"] = from_union([lambda x: to_class(CredentialsSchemeSpecification, x), from_none], self.scheme_specification)
        result["string"] = from_union([lambda x: to_class(CredentialsString, x), from_none], self.string)
        result["system"] = from_union([lambda x: to_class(System, x), from_none], self.system)
        result["uploaded"] = from_union([lambda x: to_class(CredentialsUploaded, x), from_none], self.uploaded)
        result["user"] = from_union([lambda x: to_class(CredentialsUser, x), from_none], self.user)
        result["userCredentialsProvider"] = from_union([lambda x: to_class(UserCredentialsProvider, x), from_none], self.user_credentials_provider)
        result["usernamePassword"] = from_union([lambda x: to_class(CredentialsUsernamePassword, x), from_none], self.username_password)
        return result


@dataclass
class ProviderFilter:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ProviderFilter':
        assert isinstance(obj, dict)
        return ProviderFilter()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Restriction:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Restriction':
        assert isinstance(obj, dict)
        return Restriction()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class TypeFilter:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'TypeFilter':
        assert isinstance(obj, dict)
        return TypeFilter()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Configuration:
    provider_filter: Optional[ProviderFilter] = None
    restrictions: Optional[List[Restriction]] = None
    type_filter: Optional[TypeFilter] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Configuration':
        assert isinstance(obj, dict)
        provider_filter = from_union([ProviderFilter.from_dict, from_none], obj.get("providerFilter"))
        restrictions = from_union([lambda x: from_list(Restriction.from_dict, x), from_none], obj.get("restrictions"))
        type_filter = from_union([TypeFilter.from_dict, from_none], obj.get("typeFilter"))
        return Configuration(provider_filter, restrictions, type_filter)

    def to_dict(self) -> dict:
        result: dict = {}
        result["providerFilter"] = from_union([lambda x: to_class(ProviderFilter, x), from_none], self.provider_filter)
        result["restrictions"] = from_union([lambda x: from_list(lambda x: to_class(Restriction, x), x), from_none], self.restrictions)
        result["typeFilter"] = from_union([lambda x: to_class(TypeFilter, x), from_none], self.type_filter)
        return result


@dataclass
class CredentialsProviderFilter:
    excludes: Any
    includes: Any
    none: Any

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsProviderFilter':
        assert isinstance(obj, dict)
        excludes = obj.get("excludes")
        includes = obj.get("includes")
        none = obj.get("none")
        return CredentialsProviderFilter(excludes, includes, none)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludes"] = self.excludes
        result["includes"] = self.includes
        result["none"] = self.none
        return result


@dataclass
class CredentialsProviderTypeRestriction:
    excludes: Any
    includes: Any

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsProviderTypeRestriction':
        assert isinstance(obj, dict)
        excludes = obj.get("excludes")
        includes = obj.get("includes")
        return CredentialsProviderTypeRestriction(excludes, includes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludes"] = self.excludes
        result["includes"] = self.includes
        return result


@dataclass
class CredentialsTypeFilter:
    excludes: Any
    includes: Any
    none: Any

    @staticmethod
    def from_dict(obj: Any) -> 'CredentialsTypeFilter':
        assert isinstance(obj, dict)
        excludes = obj.get("excludes")
        includes = obj.get("includes")
        none = obj.get("none")
        return CredentialsTypeFilter(excludes, includes, none)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludes"] = self.excludes
        result["includes"] = self.includes
        result["none"] = self.none
        return result


@dataclass
class Excludes:
    provider: Optional[str] = None
    type: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Excludes':
        assert isinstance(obj, dict)
        provider = from_union([from_str, from_none], obj.get("provider"))
        type = from_union([from_str, from_none], obj.get("type"))
        return Excludes(provider, type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["provider"] = from_union([from_str, from_none], self.provider)
        result["type"] = from_union([from_str, from_none], self.type)
        return result


@dataclass
class Includes:
    provider: Optional[str] = None
    type: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Includes':
        assert isinstance(obj, dict)
        provider = from_union([from_str, from_none], obj.get("provider"))
        type = from_union([from_str, from_none], obj.get("type"))
        return Includes(provider, type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["provider"] = from_union([from_str, from_none], self.provider)
        result["type"] = from_union([from_str, from_none], self.type)
        return result


@dataclass
class GlobalCredentialsConfigurationNone:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GlobalCredentialsConfigurationNone':
        assert isinstance(obj, dict)
        return GlobalCredentialsConfigurationNone()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier:
    configuration: Optional[Configuration] = None
    credentials_provider_filter: Optional[CredentialsProviderFilter] = None
    credentials_provider_type_restriction: Optional[CredentialsProviderTypeRestriction] = None
    credentials_type_filter: Optional[CredentialsTypeFilter] = None
    excludes: Optional[Excludes] = None
    includes: Optional[Includes] = None
    none: Optional[GlobalCredentialsConfigurationNone] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier':
        assert isinstance(obj, dict)
        configuration = from_union([Configuration.from_dict, from_none], obj.get("configuration"))
        credentials_provider_filter = from_union([CredentialsProviderFilter.from_dict, from_none], obj.get("credentialsProviderFilter"))
        credentials_provider_type_restriction = from_union([CredentialsProviderTypeRestriction.from_dict, from_none], obj.get("credentialsProviderTypeRestriction"))
        credentials_type_filter = from_union([CredentialsTypeFilter.from_dict, from_none], obj.get("credentialsTypeFilter"))
        excludes = from_union([Excludes.from_dict, from_none], obj.get("excludes"))
        includes = from_union([Includes.from_dict, from_none], obj.get("includes"))
        none = from_union([GlobalCredentialsConfigurationNone.from_dict, from_none], obj.get("none"))
        return ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier(configuration, credentials_provider_filter, credentials_provider_type_restriction, credentials_type_filter, excludes, includes, none)

    def to_dict(self) -> dict:
        result: dict = {}
        result["configuration"] = from_union([lambda x: to_class(Configuration, x), from_none], self.configuration)
        result["credentialsProviderFilter"] = from_union([lambda x: to_class(CredentialsProviderFilter, x), from_none], self.credentials_provider_filter)
        result["credentialsProviderTypeRestriction"] = from_union([lambda x: to_class(CredentialsProviderTypeRestriction, x), from_none], self.credentials_provider_type_restriction)
        result["credentialsTypeFilter"] = from_union([lambda x: to_class(CredentialsTypeFilter, x), from_none], self.credentials_type_filter)
        result["excludes"] = from_union([lambda x: to_class(Excludes, x), from_none], self.excludes)
        result["includes"] = from_union([lambda x: to_class(Includes, x), from_none], self.includes)
        result["none"] = from_union([lambda x: to_class(GlobalCredentialsConfigurationNone, x), from_none], self.none)
        return result


@dataclass
class AllProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'AllProperty':
        assert isinstance(obj, dict)
        return AllProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class All:
    description: Optional[str] = None
    name: Optional[str] = None
    properties: Optional[List[AllProperty]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'All':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([lambda x: from_list(AllProperty.from_dict, x), from_none], obj.get("properties"))
        return All(description, name, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: from_list(lambda x: to_class(AllProperty, x), x), from_none], self.properties)
        return result


@dataclass
class Always:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Always':
        assert isinstance(obj, dict)
        return Always()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsAPIToken:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsAPIToken':
        assert isinstance(obj, dict)
        return JenkinsAPIToken()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class AuthorizationMatrixNodePropertyInheritanceStrategy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'AuthorizationMatrixNodePropertyInheritanceStrategy':
        assert isinstance(obj, dict)
        return AuthorizationMatrixNodePropertyInheritanceStrategy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class AuthorizationMatrixNodeProperty:
    inheritance_strategy: Optional[AuthorizationMatrixNodePropertyInheritanceStrategy] = None
    permissions: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'AuthorizationMatrixNodeProperty':
        assert isinstance(obj, dict)
        inheritance_strategy = from_union([AuthorizationMatrixNodePropertyInheritanceStrategy.from_dict, from_none], obj.get("inheritanceStrategy"))
        permissions = from_union([from_str, from_none], obj.get("permissions"))
        return AuthorizationMatrixNodeProperty(inheritance_strategy, permissions)

    def to_dict(self) -> dict:
        result: dict = {}
        result["inheritanceStrategy"] = from_union([lambda x: to_class(AuthorizationMatrixNodePropertyInheritanceStrategy, x), from_none], self.inheritance_strategy)
        result["permissions"] = from_union([from_str, from_none], self.permissions)
        return result


@dataclass
class PurpleAuthorizationStrategy:
    project_matrix: Any
    global_matrix: Any
    legacy: Any
    logged_in_users_can_do_anything: Any
    unsecured: Any

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleAuthorizationStrategy':
        assert isinstance(obj, dict)
        project_matrix = obj.get("projectMatrix")
        global_matrix = obj.get("globalMatrix")
        legacy = obj.get("legacy")
        logged_in_users_can_do_anything = obj.get("loggedInUsersCanDoAnything")
        unsecured = obj.get("unsecured")
        return PurpleAuthorizationStrategy(project_matrix, global_matrix, legacy, logged_in_users_can_do_anything, unsecured)

    def to_dict(self) -> dict:
        result: dict = {}
        result["projectMatrix"] = self.project_matrix
        result["globalMatrix"] = self.global_matrix
        result["legacy"] = self.legacy
        result["loggedInUsersCanDoAnything"] = self.logged_in_users_can_do_anything
        result["unsecured"] = self.unsecured
        return result


@dataclass
class FluffyPrivateKeySource:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyPrivateKeySource':
        assert isinstance(obj, dict)
        return FluffyPrivateKeySource()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsBasicSSHUserPrivateKey:
    description: Optional[str] = None
    id: Optional[str] = None
    passphrase: Optional[str] = None
    private_key_source: Optional[FluffyPrivateKeySource] = None
    scope: Optional[Scope] = None
    username: Optional[str] = None
    """By default, usernames are not masked in the build log.
    You may choose to mask a credential's username if you consider it to be sensitive
    information.
    However, this can interfere with diagnostics.
    For example, if the username is a common word it will cause unrelated occurrences of that
    word to also be masked.
    
    Regardless of this setting, the username will be displayed in the selection dropdown to
    anyone permitted to reconfigure the credentials.
    """
    username_secret: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsBasicSSHUserPrivateKey':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        passphrase = from_union([from_str, from_none], obj.get("passphrase"))
        private_key_source = from_union([FluffyPrivateKeySource.from_dict, from_none], obj.get("privateKeySource"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        username = from_union([from_str, from_none], obj.get("username"))
        username_secret = from_union([from_bool, from_none], obj.get("usernameSecret"))
        return JenkinsBasicSSHUserPrivateKey(description, id, passphrase, private_key_source, scope, username, username_secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["passphrase"] = from_union([from_str, from_none], self.passphrase)
        result["privateKeySource"] = from_union([lambda x: to_class(FluffyPrivateKeySource, x), from_none], self.private_key_source)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        result["username"] = from_union([from_str, from_none], self.username)
        result["usernameSecret"] = from_union([from_bool, from_none], self.username_secret)
        return result


@dataclass
class JenkinsBatchFile:
    command: Optional[str] = None
    label: Optional[str] = None
    tool_home: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsBatchFile':
        assert isinstance(obj, dict)
        command = from_union([from_str, from_none], obj.get("command"))
        label = from_union([from_str, from_none], obj.get("label"))
        tool_home = from_union([from_str, from_none], obj.get("toolHome"))
        return JenkinsBatchFile(command, label, tool_home)

    def to_dict(self) -> dict:
        result: dict = {}
        result["command"] = from_union([from_str, from_none], self.command)
        result["label"] = from_union([from_str, from_none], self.label)
        result["toolHome"] = from_union([from_str, from_none], self.tool_home)
        return result


@dataclass
class BranchStatusColumn:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'BranchStatusColumn':
        assert isinstance(obj, dict)
        return BranchStatusColumn()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class BuildButton:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'BuildButton':
        assert isinstance(obj, dict)
        return BuildButton()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FluffyKeyStoreSource:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The source of the certificate.
    """
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyKeyStoreSource':
        assert isinstance(obj, dict)
        return FluffyKeyStoreSource()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsCertificate:
    description: Optional[str] = None
    id: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The source of the certificate.
    """
    key_store_source: Optional[FluffyKeyStoreSource] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The password. The use of separate integrity and encryption passwords is not supported.
    """
    password: Optional[str] = None
    scope: Optional[Scope] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsCertificate':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        key_store_source = from_union([FluffyKeyStoreSource.from_dict, from_none], obj.get("keyStoreSource"))
        password = from_union([from_str, from_none], obj.get("password"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        return JenkinsCertificate(description, id, key_store_source, password, scope)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["keyStoreSource"] = from_union([lambda x: to_class(FluffyKeyStoreSource, x), from_none], self.key_store_source)
        result["password"] = from_union([from_str, from_none], self.password)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        return result


@dataclass
class JenkinsCommand:
    """Single command to launch an agent program, which controls the agent
    computer and communicates with the controller. Jenkins assumes that
    the executed program launches the agent.jar program on the correct
    machine.
    
    
    A copy of agent.jar can be downloaded from here.
    
    
    
    In a simple case, this could be
    something like ssh hostname java -jar ~/bin/agent.jar.
    
    
    
    Note: the command can't rely on a shell to parse things, e.g. echo foo &gt; bar; baz.
    If you need to do that, either use
    sh -c or write the expression into a script and point to the script.
    
    
    
    It is often a good idea to write a small shell script, like the following, on an
    agent
    so that you can control the location of Java and/or agent.jar, as well as set up any
    environment variables specific to this node, such as PATH.
    
    
    
    #!/bin/sh
    exec java -jar ~/bin/agent.jar
    
    
    
    You can use any command to run a process on the agent machine, such as RSH,
    as long as stdin/stdout of the process on the controller will be connected to
    those of java -jar ~/bin/agent.jar on the agent machine eventually.
    
    
    
    In a larger deployment, it is also worth considering to load agent.jar from
    a NFS-mounted common location, so that you don't have to update this file
    on every agent machines every time you update Jenkins.
    
    
    
    Setting this to ssh -v hostname may be useful for debugging connectivity
    issue.
    """
    command: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsCommand':
        assert isinstance(obj, dict)
        command = from_union([from_str, from_none], obj.get("command"))
        return JenkinsCommand(command)

    def to_dict(self) -> dict:
        result: dict = {}
        result["command"] = from_union([from_str, from_none], self.command)
        return result


@dataclass
class ComputerLauncher:
    jnlp: Any
    ssh: Any
    command: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ComputerLauncher':
        assert isinstance(obj, dict)
        jnlp = obj.get("jnlp")
        ssh = obj.get("ssh")
        command = obj.get("command")
        return ComputerLauncher(jnlp, ssh, command)

    def to_dict(self) -> dict:
        result: dict = {}
        result["jnlp"] = self.jnlp
        result["ssh"] = self.ssh
        result["command"] = self.command
        return result


@dataclass
class JenkinsCredentials:
    file: Any
    string: Any
    basic_ssh_user_private_key: Any
    certificate: Any
    username_password: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsCredentials':
        assert isinstance(obj, dict)
        file = obj.get("file")
        string = obj.get("string")
        basic_ssh_user_private_key = obj.get("basicSSHUserPrivateKey")
        certificate = obj.get("certificate")
        username_password = obj.get("usernamePassword")
        return JenkinsCredentials(file, string, basic_ssh_user_private_key, certificate, username_password)

    def to_dict(self) -> dict:
        result: dict = {}
        result["file"] = self.file
        result["string"] = self.string
        result["basicSSHUserPrivateKey"] = self.basic_ssh_user_private_key
        result["certificate"] = self.certificate
        result["usernamePassword"] = self.username_password
        return result


@dataclass
class PurpleCrumbIssuer:
    standard: Any

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleCrumbIssuer':
        assert isinstance(obj, dict)
        standard = obj.get("standard")
        return PurpleCrumbIssuer(standard)

    def to_dict(self) -> dict:
        result: dict = {}
        result["standard"] = self.standard
        return result


@dataclass
class Demand:
    idle_delay: Optional[int] = None
    in_demand_delay: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Demand':
        assert isinstance(obj, dict)
        idle_delay = from_union([from_int, from_none], obj.get("idleDelay"))
        in_demand_delay = from_union([from_int, from_none], obj.get("inDemandDelay"))
        return Demand(idle_delay, in_demand_delay)

    def to_dict(self) -> dict:
        result: dict = {}
        result["idleDelay"] = from_union([from_int, from_none], self.idle_delay)
        result["inDemandDelay"] = from_union([from_int, from_none], self.in_demand_delay)
        return result


@dataclass
class DescriptionColumn:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'DescriptionColumn':
        assert isinstance(obj, dict)
        return DescriptionColumn()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FluffyPrivateKey:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyPrivateKey':
        assert isinstance(obj, dict)
        return FluffyPrivateKey()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsDirectEntry:
    private_key: Optional[FluffyPrivateKey] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsDirectEntry':
        assert isinstance(obj, dict)
        private_key = from_union([FluffyPrivateKey.from_dict, from_none], obj.get("privateKey"))
        return JenkinsDirectEntry(private_key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["privateKey"] = from_union([lambda x: to_class(FluffyPrivateKey, x), from_none], self.private_key)
        return result


@dataclass
class FluffySpecification:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffySpecification':
        assert isinstance(obj, dict)
        return FluffySpecification()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsDomain:
    description: Optional[str] = None
    name: Optional[str] = None
    specifications: Optional[List[FluffySpecification]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsDomain':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        name = from_union([from_str, from_none], obj.get("name"))
        specifications = from_union([lambda x: from_list(FluffySpecification.from_dict, x), from_none], obj.get("specifications"))
        return JenkinsDomain(description, name, specifications)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["name"] = from_union([from_str, from_none], self.name)
        result["specifications"] = from_union([lambda x: from_list(lambda x: to_class(FluffySpecification, x), x), from_none], self.specifications)
        return result


@dataclass
class FluffyCredential:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyCredential':
        assert isinstance(obj, dict)
        return FluffyCredential()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FluffyDomain:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyDomain':
        assert isinstance(obj, dict)
        return FluffyDomain()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsDomainCredentials:
    credentials: Optional[List[FluffyCredential]] = None
    domain: Optional[FluffyDomain] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsDomainCredentials':
        assert isinstance(obj, dict)
        credentials = from_union([lambda x: from_list(FluffyCredential.from_dict, x), from_none], obj.get("credentials"))
        domain = from_union([FluffyDomain.from_dict, from_none], obj.get("domain"))
        return JenkinsDomainCredentials(credentials, domain)

    def to_dict(self) -> dict:
        result: dict = {}
        result["credentials"] = from_union([lambda x: from_list(lambda x: to_class(FluffyCredential, x), x), from_none], self.credentials)
        result["domain"] = from_union([lambda x: to_class(FluffyDomain, x), from_none], self.domain)
        return result


@dataclass
class JenkinsDomainSpecification:
    scheme_specification: Any
    hostname_port_specification: Any
    path_specification: Any
    hostname_specification: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsDomainSpecification':
        assert isinstance(obj, dict)
        scheme_specification = obj.get("schemeSpecification")
        hostname_port_specification = obj.get("hostnamePortSpecification")
        path_specification = obj.get("pathSpecification")
        hostname_specification = obj.get("hostnameSpecification")
        return JenkinsDomainSpecification(scheme_specification, hostname_port_specification, path_specification, hostname_specification)

    def to_dict(self) -> dict:
        result: dict = {}
        result["schemeSpecification"] = self.scheme_specification
        result["hostnamePortSpecification"] = self.hostname_port_specification
        result["pathSpecification"] = self.path_specification
        result["hostnameSpecification"] = self.hostname_specification
        return result


@dataclass
class Jenkins:
    """Allows disabling Remoting Work Directory for the agent.
    In such case the agent will be running in the legacy mode without logging enabled by
    default.
    """
    disabled: Optional[bool] = None
    """If defined, Remoting will fail at startup if the target work directory is missing.
    The option may be used to detect infrastructure issues like failed mount.
    """
    fail_if_work_dir_is_missing: Optional[bool] = None
    """Defines a storage directory for the internal data.
    This directory will be created within the Remoting working directory.
    """
    internal_dir: Optional[str] = None
    """If defined, a custom Remoting work directory will be used instead of the Agent Root
    Directory.
    This option has no environment variable resolution so far, it is recommended to use only
    absolute paths.
    """
    work_dir_path: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Jenkins':
        assert isinstance(obj, dict)
        disabled = from_union([from_bool, from_none], obj.get("disabled"))
        fail_if_work_dir_is_missing = from_union([from_bool, from_none], obj.get("failIfWorkDirIsMissing"))
        internal_dir = from_union([from_str, from_none], obj.get("internalDir"))
        work_dir_path = from_union([from_str, from_none], obj.get("workDirPath"))
        return Jenkins(disabled, fail_if_work_dir_is_missing, internal_dir, work_dir_path)

    def to_dict(self) -> dict:
        result: dict = {}
        result["disabled"] = from_union([from_bool, from_none], self.disabled)
        result["failIfWorkDirIsMissing"] = from_union([from_bool, from_none], self.fail_if_work_dir_is_missing)
        result["internalDir"] = from_union([from_str, from_none], self.internal_dir)
        result["workDirPath"] = from_union([from_str, from_none], self.work_dir_path)
        return result


@dataclass
class Entry:
    key: Optional[str] = None
    value: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Entry':
        assert isinstance(obj, dict)
        key = from_union([from_str, from_none], obj.get("key"))
        value = from_union([from_str, from_none], obj.get("value"))
        return Entry(key, value)

    def to_dict(self) -> dict:
        result: dict = {}
        result["key"] = from_union([from_str, from_none], self.key)
        result["value"] = from_union([from_str, from_none], self.value)
        return result


@dataclass
class FluffySecretBytes:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffySecretBytes':
        assert isinstance(obj, dict)
        return FluffySecretBytes()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsFile:
    description: Optional[str] = None
    file_name: Optional[str] = None
    id: Optional[str] = None
    scope: Optional[Scope] = None
    secret_bytes: Optional[FluffySecretBytes] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsFile':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        file_name = from_union([from_str, from_none], obj.get("fileName"))
        id = from_union([from_str, from_none], obj.get("id"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        secret_bytes = from_union([FluffySecretBytes.from_dict, from_none], obj.get("secretBytes"))
        return JenkinsFile(description, file_name, id, scope, secret_bytes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["fileName"] = from_union([from_str, from_none], self.file_name)
        result["id"] = from_union([from_str, from_none], self.id)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        result["secretBytes"] = from_union([lambda x: to_class(FluffySecretBytes, x), from_none], self.secret_bytes)
        return result


@dataclass
class GitBranchSpecifierColumn:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GitBranchSpecifierColumn':
        assert isinstance(obj, dict)
        return GitBranchSpecifierColumn()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsHostnamePortSpecification:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of excluded hostnames. (The * wildcard is permitted in
    hostnames,
    for example: jenkins-ci.org:*, *.jenkins-ci.org:80, jenkinsci.github.io:443.)
    
    The empty list implies no hostname:port is excluded. The excludes list is processed after
    the includes
    list.
    """
    excludes: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of included hostnames. (The * wildcard is permitted in
    hostnames,
    for example: jenkins-ci.org:*, *.jenkins-ci.org:80, jenkinsci.github.io:443.)
    
    The empty list implies no hostname:port is excluded. The excludes list is processed after
    the includes
    list.
    """
    includes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsHostnamePortSpecification':
        assert isinstance(obj, dict)
        excludes = from_union([from_str, from_none], obj.get("excludes"))
        includes = from_union([from_str, from_none], obj.get("includes"))
        return JenkinsHostnamePortSpecification(excludes, includes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludes"] = from_union([from_str, from_none], self.excludes)
        result["includes"] = from_union([from_str, from_none], self.includes)
        return result


@dataclass
class JenkinsHostnameSpecification:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of excluded hostnames. (The * wildcard is permitted in
    hostnames,
    for example: jenkins-ci.org, *.jenkins-ci.org, jenkinsci.github.io.)
    
    The empty list implies no hostnames are excluded. The excludes list is processed after
    the includes list.
    """
    excludes: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of included hostnames. (The * wildcard is permitted in
    hostnames,
    for example: jenkins-ci.org, *.jenkins-ci.org, jenkinsci.github.io.)
    
    The empty list implies no hostnames are excluded. The excludes list is processed after
    the includes list.
    """
    includes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsHostnameSpecification':
        assert isinstance(obj, dict)
        excludes = from_union([from_str, from_none], obj.get("excludes"))
        includes = from_union([from_str, from_none], obj.get("includes"))
        return JenkinsHostnameSpecification(excludes, includes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludes"] = from_union([from_str, from_none], self.excludes)
        result["includes"] = from_union([from_str, from_none], self.includes)
        return result


@dataclass
class JenkinsInheritanceStrategy:
    inheriting_global: Any
    non_inheriting: Any
    inheriting: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsInheritanceStrategy':
        assert isinstance(obj, dict)
        inheriting_global = obj.get("inheritingGlobal")
        non_inheriting = obj.get("nonInheriting")
        inheriting = obj.get("inheriting")
        return JenkinsInheritanceStrategy(inheriting_global, non_inheriting, inheriting)

    def to_dict(self) -> dict:
        result: dict = {}
        result["inheritingGlobal"] = self.inheriting_global
        result["nonInheriting"] = self.non_inheriting
        result["inheriting"] = self.inheriting
        return result


@dataclass
class Inheriting:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Inheriting':
        assert isinstance(obj, dict)
        return Inheriting()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class InheritingGlobal:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'InheritingGlobal':
        assert isinstance(obj, dict)
        return InheritingGlobal()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ItemColumn:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ItemColumn':
        assert isinstance(obj, dict)
        return ItemColumn()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JDKs:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'JDKs':
        assert isinstance(obj, dict)
        return JDKs()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleProperty':
        assert isinstance(obj, dict)
        return PurpleProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsJDK:
    home: Optional[str] = None
    name: Optional[str] = None
    properties: Optional[List[PurpleProperty]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsJDK':
        assert isinstance(obj, dict)
        home = from_union([from_str, from_none], obj.get("home"))
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([lambda x: from_list(PurpleProperty.from_dict, x), from_none], obj.get("properties"))
        return JenkinsJDK(home, name, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["home"] = from_union([from_str, from_none], self.home)
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: from_list(lambda x: to_class(PurpleProperty, x), x), from_none], self.properties)
        return result


@dataclass
class JenkinsJDKInstaller:
    accept_license: Optional[bool] = None
    id: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsJDKInstaller':
        assert isinstance(obj, dict)
        accept_license = from_union([from_bool, from_none], obj.get("acceptLicense"))
        id = from_union([from_str, from_none], obj.get("id"))
        return JenkinsJDKInstaller(accept_license, id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["acceptLicense"] = from_union([from_bool, from_none], self.accept_license)
        result["id"] = from_union([from_str, from_none], self.id)
        return result


@dataclass
class FluffyAuthorizationStrategy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyAuthorizationStrategy':
        assert isinstance(obj, dict)
        return FluffyAuthorizationStrategy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Cloud:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Cloud':
        assert isinstance(obj, dict)
        return Cloud()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FluffyCrumbIssuer:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyCrumbIssuer':
        assert isinstance(obj, dict)
        return FluffyCrumbIssuer()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class GlobalNodeProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GlobalNodeProperty':
        assert isinstance(obj, dict)
        return GlobalNodeProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LabelAtomProperties:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LabelAtomProperties':
        assert isinstance(obj, dict)
        return LabelAtomProperties()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LabelAtomElement:
    name: Optional[str] = None
    properties: Optional[LabelAtomProperties] = None

    @staticmethod
    def from_dict(obj: Any) -> 'LabelAtomElement':
        assert isinstance(obj, dict)
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([LabelAtomProperties.from_dict, from_none], obj.get("properties"))
        return LabelAtomElement(name, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: to_class(LabelAtomProperties, x), from_none], self.properties)
        return result


@dataclass
class PurpleLog:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleLog':
        assert isinstance(obj, dict)
        return PurpleLog()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleMarkupFormatter:
    """In such places as project description, user description, view description, and build
    description,
    Jenkins allows users to enter some free-form text that describes something.
    
    This configuration determines how such free-form text is converted to HTML. By default,
    Jenkins treats
    the text as HTML and use it as-is unmodified (and this is default mainly because of the
    backward compatibility.)
    
    
    While this is convenient and people often use it to load &lt;iframe>, &lt;script>. and so
    on to
    mash up data from other sources, this capability enables malicious users to mount
    XSS attacks.
    If the risk outweighs the benefit, install additional markup formatter plugins and use
    them.
    """
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleMarkupFormatter':
        assert isinstance(obj, dict)
        return PurpleMarkupFormatter()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


class Mode(Enum):
    EXCLUSIVE = "EXCLUSIVE"
    NORMAL = "NORMAL"


@dataclass
class PurpleMyViewsTabBar:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleMyViewsTabBar':
        assert isinstance(obj, dict)
        return PurpleMyViewsTabBar()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleNodeProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleNodeProperty':
        assert isinstance(obj, dict)
        return PurpleNodeProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class NodeElement:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'NodeElement':
        assert isinstance(obj, dict)
        return NodeElement()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PrimaryView:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PrimaryView':
        assert isinstance(obj, dict)
        return PrimaryView()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleProjectNamingStrategy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleProjectNamingStrategy':
        assert isinstance(obj, dict)
        return PurpleProjectNamingStrategy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleProxy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleProxy':
        assert isinstance(obj, dict)
        return PurpleProxy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleRemotingSecurity:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleRemotingSecurity':
        assert isinstance(obj, dict)
        return PurpleRemotingSecurity()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleSecurityRealm:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleSecurityRealm':
        assert isinstance(obj, dict)
        return PurpleSecurityRealm()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleUpdateCenter:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleUpdateCenter':
        assert isinstance(obj, dict)
        return PurpleUpdateCenter()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ViewElement:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ViewElement':
        assert isinstance(obj, dict)
        return ViewElement()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleViewsTabBar:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleViewsTabBar':
        assert isinstance(obj, dict)
        return PurpleViewsTabBar()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsClass:
    agent_protocols: Optional[str] = None
    authorization_strategy: Optional[FluffyAuthorizationStrategy] = None
    clouds: Optional[List[Cloud]] = None
    crumb_issuer: Optional[FluffyCrumbIssuer] = None
    disabled_administrative_monitors: Optional[str] = None
    disable_remember_me: Optional[bool] = None
    global_node_properties: Optional[List[GlobalNodeProperty]] = None
    label_atoms: Optional[List[LabelAtomElement]] = None
    label_string: Optional[str] = None
    log: Optional[PurpleLog] = None
    """In such places as project description, user description, view description, and build
    description,
    Jenkins allows users to enter some free-form text that describes something.
    
    This configuration determines how such free-form text is converted to HTML. By default,
    Jenkins treats
    the text as HTML and use it as-is unmodified (and this is default mainly because of the
    backward compatibility.)
    
    
    While this is convenient and people often use it to load &lt;iframe>, &lt;script>. and so
    on to
    mash up data from other sources, this capability enables malicious users to mount
    XSS attacks.
    If the risk outweighs the benefit, install additional markup formatter plugins and use
    them.
    """
    markup_formatter: Optional[PurpleMarkupFormatter] = None
    mode: Optional[Mode] = None
    my_views_tab_bar: Optional[PurpleMyViewsTabBar] = None
    node_name: Optional[str] = None
    node_properties: Optional[List[PurpleNodeProperty]] = None
    nodes: Optional[List[NodeElement]] = None
    no_usage_statistics: Optional[bool] = None
    num_executors: Optional[int] = None
    primary_view: Optional[PrimaryView] = None
    project_naming_strategy: Optional[PurpleProjectNamingStrategy] = None
    proxy: Optional[PurpleProxy] = None
    quiet_period: Optional[int] = None
    remoting_security: Optional[PurpleRemotingSecurity] = None
    scm_checkout_retry_count: Optional[int] = None
    security_realm: Optional[PurpleSecurityRealm] = None
    slave_agent_port: Optional[int] = None
    system_message: Optional[str] = None
    update_center: Optional[PurpleUpdateCenter] = None
    views: Optional[List[ViewElement]] = None
    views_tab_bar: Optional[PurpleViewsTabBar] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsClass':
        assert isinstance(obj, dict)
        agent_protocols = from_union([from_str, from_none], obj.get("agentProtocols"))
        authorization_strategy = from_union([FluffyAuthorizationStrategy.from_dict, from_none], obj.get("authorizationStrategy"))
        clouds = from_union([lambda x: from_list(Cloud.from_dict, x), from_none], obj.get("clouds"))
        crumb_issuer = from_union([FluffyCrumbIssuer.from_dict, from_none], obj.get("crumbIssuer"))
        disabled_administrative_monitors = from_union([from_str, from_none], obj.get("disabledAdministrativeMonitors"))
        disable_remember_me = from_union([from_bool, from_none], obj.get("disableRememberMe"))
        global_node_properties = from_union([lambda x: from_list(GlobalNodeProperty.from_dict, x), from_none], obj.get("globalNodeProperties"))
        label_atoms = from_union([lambda x: from_list(LabelAtomElement.from_dict, x), from_none], obj.get("labelAtoms"))
        label_string = from_union([from_str, from_none], obj.get("labelString"))
        log = from_union([PurpleLog.from_dict, from_none], obj.get("log"))
        markup_formatter = from_union([PurpleMarkupFormatter.from_dict, from_none], obj.get("markupFormatter"))
        mode = from_union([Mode, from_none], obj.get("mode"))
        my_views_tab_bar = from_union([PurpleMyViewsTabBar.from_dict, from_none], obj.get("myViewsTabBar"))
        node_name = from_union([from_str, from_none], obj.get("nodeName"))
        node_properties = from_union([lambda x: from_list(PurpleNodeProperty.from_dict, x), from_none], obj.get("nodeProperties"))
        nodes = from_union([lambda x: from_list(NodeElement.from_dict, x), from_none], obj.get("nodes"))
        no_usage_statistics = from_union([from_bool, from_none], obj.get("noUsageStatistics"))
        num_executors = from_union([from_int, from_none], obj.get("numExecutors"))
        primary_view = from_union([PrimaryView.from_dict, from_none], obj.get("primaryView"))
        project_naming_strategy = from_union([PurpleProjectNamingStrategy.from_dict, from_none], obj.get("projectNamingStrategy"))
        proxy = from_union([PurpleProxy.from_dict, from_none], obj.get("proxy"))
        quiet_period = from_union([from_int, from_none], obj.get("quietPeriod"))
        remoting_security = from_union([PurpleRemotingSecurity.from_dict, from_none], obj.get("remotingSecurity"))
        scm_checkout_retry_count = from_union([from_int, from_none], obj.get("scmCheckoutRetryCount"))
        security_realm = from_union([PurpleSecurityRealm.from_dict, from_none], obj.get("securityRealm"))
        slave_agent_port = from_union([from_int, from_none], obj.get("slaveAgentPort"))
        system_message = from_union([from_str, from_none], obj.get("systemMessage"))
        update_center = from_union([PurpleUpdateCenter.from_dict, from_none], obj.get("updateCenter"))
        views = from_union([lambda x: from_list(ViewElement.from_dict, x), from_none], obj.get("views"))
        views_tab_bar = from_union([PurpleViewsTabBar.from_dict, from_none], obj.get("viewsTabBar"))
        return JenkinsClass(agent_protocols, authorization_strategy, clouds, crumb_issuer, disabled_administrative_monitors, disable_remember_me, global_node_properties, label_atoms, label_string, log, markup_formatter, mode, my_views_tab_bar, node_name, node_properties, nodes, no_usage_statistics, num_executors, primary_view, project_naming_strategy, proxy, quiet_period, remoting_security, scm_checkout_retry_count, security_realm, slave_agent_port, system_message, update_center, views, views_tab_bar)

    def to_dict(self) -> dict:
        result: dict = {}
        result["agentProtocols"] = from_union([from_str, from_none], self.agent_protocols)
        result["authorizationStrategy"] = from_union([lambda x: to_class(FluffyAuthorizationStrategy, x), from_none], self.authorization_strategy)
        result["clouds"] = from_union([lambda x: from_list(lambda x: to_class(Cloud, x), x), from_none], self.clouds)
        result["crumbIssuer"] = from_union([lambda x: to_class(FluffyCrumbIssuer, x), from_none], self.crumb_issuer)
        result["disabledAdministrativeMonitors"] = from_union([from_str, from_none], self.disabled_administrative_monitors)
        result["disableRememberMe"] = from_union([from_bool, from_none], self.disable_remember_me)
        result["globalNodeProperties"] = from_union([lambda x: from_list(lambda x: to_class(GlobalNodeProperty, x), x), from_none], self.global_node_properties)
        result["labelAtoms"] = from_union([lambda x: from_list(lambda x: to_class(LabelAtomElement, x), x), from_none], self.label_atoms)
        result["labelString"] = from_union([from_str, from_none], self.label_string)
        result["log"] = from_union([lambda x: to_class(PurpleLog, x), from_none], self.log)
        result["markupFormatter"] = from_union([lambda x: to_class(PurpleMarkupFormatter, x), from_none], self.markup_formatter)
        result["mode"] = from_union([lambda x: to_enum(Mode, x), from_none], self.mode)
        result["myViewsTabBar"] = from_union([lambda x: to_class(PurpleMyViewsTabBar, x), from_none], self.my_views_tab_bar)
        result["nodeName"] = from_union([from_str, from_none], self.node_name)
        result["nodeProperties"] = from_union([lambda x: from_list(lambda x: to_class(PurpleNodeProperty, x), x), from_none], self.node_properties)
        result["nodes"] = from_union([lambda x: from_list(lambda x: to_class(NodeElement, x), x), from_none], self.nodes)
        result["noUsageStatistics"] = from_union([from_bool, from_none], self.no_usage_statistics)
        result["numExecutors"] = from_union([from_int, from_none], self.num_executors)
        result["primaryView"] = from_union([lambda x: to_class(PrimaryView, x), from_none], self.primary_view)
        result["projectNamingStrategy"] = from_union([lambda x: to_class(PurpleProjectNamingStrategy, x), from_none], self.project_naming_strategy)
        result["proxy"] = from_union([lambda x: to_class(PurpleProxy, x), from_none], self.proxy)
        result["quietPeriod"] = from_union([from_int, from_none], self.quiet_period)
        result["remotingSecurity"] = from_union([lambda x: to_class(PurpleRemotingSecurity, x), from_none], self.remoting_security)
        result["scmCheckoutRetryCount"] = from_union([from_int, from_none], self.scm_checkout_retry_count)
        result["securityRealm"] = from_union([lambda x: to_class(PurpleSecurityRealm, x), from_none], self.security_realm)
        result["slaveAgentPort"] = from_union([from_int, from_none], self.slave_agent_port)
        result["systemMessage"] = from_union([from_str, from_none], self.system_message)
        result["updateCenter"] = from_union([lambda x: to_class(PurpleUpdateCenter, x), from_none], self.update_center)
        result["views"] = from_union([lambda x: from_list(lambda x: to_class(ViewElement, x), x), from_none], self.views)
        result["viewsTabBar"] = from_union([lambda x: to_class(PurpleViewsTabBar, x), from_none], self.views_tab_bar)
        return result


@dataclass
class WorkDirSettings:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'WorkDirSettings':
        assert isinstance(obj, dict)
        return WorkDirSettings()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Jnlp:
    tunnel: Optional[str] = None
    """If the agent JVM should be launched with additional VM arguments, such as "-Xmx256m",
    specify those here. List of all the options are available
    here.
    """
    vmargs: Optional[str] = None
    """Use WebSocket to connect to the Jenkins master rather than the TCP port.
    See JEP-222 for background.
    """
    web_socket: Optional[bool] = None
    work_dir_settings: Optional[WorkDirSettings] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Jnlp':
        assert isinstance(obj, dict)
        tunnel = from_union([from_str, from_none], obj.get("tunnel"))
        vmargs = from_union([from_str, from_none], obj.get("vmargs"))
        web_socket = from_union([from_bool, from_none], obj.get("webSocket"))
        work_dir_settings = from_union([WorkDirSettings.from_dict, from_none], obj.get("workDirSettings"))
        return Jnlp(tunnel, vmargs, web_socket, work_dir_settings)

    def to_dict(self) -> dict:
        result: dict = {}
        result["tunnel"] = from_union([from_str, from_none], self.tunnel)
        result["vmargs"] = from_union([from_str, from_none], self.vmargs)
        result["webSocket"] = from_union([from_bool, from_none], self.web_socket)
        result["workDirSettings"] = from_union([lambda x: to_class(WorkDirSettings, x), from_none], self.work_dir_settings)
        return result


@dataclass
class JobName:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'JobName':
        assert isinstance(obj, dict)
        return JobName()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsKeyStoreSource:
    uploaded: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsKeyStoreSource':
        assert isinstance(obj, dict)
        uploaded = obj.get("uploaded")
        return JenkinsKeyStoreSource(uploaded)

    def to_dict(self) -> dict:
        result: dict = {}
        result["uploaded"] = self.uploaded
        return result


@dataclass
class KnownHostsFileKeyVerificationStrategy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'KnownHostsFileKeyVerificationStrategy':
        assert isinstance(obj, dict)
        return KnownHostsFileKeyVerificationStrategy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LabelAtomProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LabelAtomProperty':
        assert isinstance(obj, dict)
        return LabelAtomProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PurpleLabelAtom:
    name: Optional[str] = None
    properties: Optional[List[LabelAtomProperty]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleLabelAtom':
        assert isinstance(obj, dict)
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([lambda x: from_list(LabelAtomProperty.from_dict, x), from_none], obj.get("properties"))
        return PurpleLabelAtom(name, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: from_list(lambda x: to_class(LabelAtomProperty, x), x), from_none], self.properties)
        return result


@dataclass
class LabelAtoms:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LabelAtoms':
        assert isinstance(obj, dict)
        return LabelAtoms()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LastDuration:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LastDuration':
        assert isinstance(obj, dict)
        return LastDuration()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LastFailure:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LastFailure':
        assert isinstance(obj, dict)
        return LastFailure()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LastStable:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LastStable':
        assert isinstance(obj, dict)
        return LastStable()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LastSuccess:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LastSuccess':
        assert isinstance(obj, dict)
        return LastSuccess()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LegacyCAPTCHASupport:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LegacyCAPTCHASupport':
        assert isinstance(obj, dict)
        return LegacyCAPTCHASupport()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Legacy:
    captcha_support: Optional[LegacyCAPTCHASupport] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Legacy':
        assert isinstance(obj, dict)
        captcha_support = from_union([LegacyCAPTCHASupport.from_dict, from_none], obj.get("captchaSupport"))
        return Legacy(captcha_support)

    def to_dict(self) -> dict:
        result: dict = {}
        result["captchaSupport"] = from_union([lambda x: to_class(LegacyCAPTCHASupport, x), from_none], self.captcha_support)
        return result


@dataclass
class Column:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Column':
        assert isinstance(obj, dict)
        return Column()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JobFilter:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'JobFilter':
        assert isinstance(obj, dict)
        return JobFilter()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ListProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ListProperty':
        assert isinstance(obj, dict)
        return ListProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ListClass:
    columns: Optional[List[Column]] = None
    description: Optional[str] = None
    include_regex: Optional[str] = None
    job_filters: Optional[List[JobFilter]] = None
    job_names: Optional[str] = None
    name: Optional[str] = None
    properties: Optional[List[ListProperty]] = None
    recurse: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ListClass':
        assert isinstance(obj, dict)
        columns = from_union([lambda x: from_list(Column.from_dict, x), from_none], obj.get("columns"))
        description = from_union([from_str, from_none], obj.get("description"))
        include_regex = from_union([from_str, from_none], obj.get("includeRegex"))
        job_filters = from_union([lambda x: from_list(JobFilter.from_dict, x), from_none], obj.get("jobFilters"))
        job_names = from_union([from_str, from_none], obj.get("jobNames"))
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([lambda x: from_list(ListProperty.from_dict, x), from_none], obj.get("properties"))
        recurse = from_union([from_bool, from_none], obj.get("recurse"))
        return ListClass(columns, description, include_regex, job_filters, job_names, name, properties, recurse)

    def to_dict(self) -> dict:
        result: dict = {}
        result["columns"] = from_union([lambda x: from_list(lambda x: to_class(Column, x), x), from_none], self.columns)
        result["description"] = from_union([from_str, from_none], self.description)
        result["includeRegex"] = from_union([from_str, from_none], self.include_regex)
        result["jobFilters"] = from_union([lambda x: from_list(lambda x: to_class(JobFilter, x), x), from_none], self.job_filters)
        result["jobNames"] = from_union([from_str, from_none], self.job_names)
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: from_list(lambda x: to_class(ListProperty, x), x), from_none], self.properties)
        result["recurse"] = from_union([from_bool, from_none], self.recurse)
        return result


@dataclass
class ListViewColumn:
    job_name: Any
    last_duration: Any
    build_button: Any
    git_branch_specifier_column: Any
    last_stable: Any
    weather: Any
    branch_status_column: Any
    item_column: Any
    last_success: Any
    last_failure: Any
    description_column: Any
    status: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ListViewColumn':
        assert isinstance(obj, dict)
        job_name = obj.get("jobName")
        last_duration = obj.get("lastDuration")
        build_button = obj.get("buildButton")
        git_branch_specifier_column = obj.get("gitBranchSpecifierColumn")
        last_stable = obj.get("lastStable")
        weather = obj.get("weather")
        branch_status_column = obj.get("branchStatusColumn")
        item_column = obj.get("itemColumn")
        last_success = obj.get("lastSuccess")
        last_failure = obj.get("lastFailure")
        description_column = obj.get("descriptionColumn")
        status = obj.get("status")
        return ListViewColumn(job_name, last_duration, build_button, git_branch_specifier_column, last_stable, weather, branch_status_column, item_column, last_success, last_failure, description_column, status)

    def to_dict(self) -> dict:
        result: dict = {}
        result["jobName"] = self.job_name
        result["lastDuration"] = self.last_duration
        result["buildButton"] = self.build_button
        result["gitBranchSpecifierColumn"] = self.git_branch_specifier_column
        result["lastStable"] = self.last_stable
        result["weather"] = self.weather
        result["branchStatusColumn"] = self.branch_status_column
        result["itemColumn"] = self.item_column
        result["lastSuccess"] = self.last_success
        result["lastFailure"] = self.last_failure
        result["descriptionColumn"] = self.description_column
        result["status"] = self.status
        return result


@dataclass
class LocalCAPTCHASupport:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LocalCAPTCHASupport':
        assert isinstance(obj, dict)
        return LocalCAPTCHASupport()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UserProperties:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UserProperties':
        assert isinstance(obj, dict)
        return UserProperties()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UserElement:
    description: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None
    password: Optional[str] = None
    properties: Optional[UserProperties] = None

    @staticmethod
    def from_dict(obj: Any) -> 'UserElement':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        name = from_union([from_str, from_none], obj.get("name"))
        password = from_union([from_str, from_none], obj.get("password"))
        properties = from_union([UserProperties.from_dict, from_none], obj.get("properties"))
        return UserElement(description, id, name, password, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["name"] = from_union([from_str, from_none], self.name)
        result["password"] = from_union([from_str, from_none], self.password)
        result["properties"] = from_union([lambda x: to_class(UserProperties, x), from_none], self.properties)
        return result


@dataclass
class Local:
    """This option allows users to create accounts by themselves, via the "sign up" link on the
    top right shoulder of the page.
    Make sure to not grant significant permissions to authenticated users, as anyone on the
    network will be able to get them.
    
    When this checkbox is unchecked, someone with the administrator role would have to create
    accounts.
    
    By default, Jenkins does not use captcha verification if the user creates an account by
    themself.
    If you'd like to enable captcha verification, install a captcha support plugin, e.g. the
    Jenkins
    JCaptcha Plugin.
    """
    allows_signup: Optional[bool] = None
    captcha_support: Optional[LocalCAPTCHASupport] = None
    enable_captcha: Optional[bool] = None
    users: Optional[List[UserElement]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Local':
        assert isinstance(obj, dict)
        allows_signup = from_union([from_bool, from_none], obj.get("allowsSignup"))
        captcha_support = from_union([LocalCAPTCHASupport.from_dict, from_none], obj.get("captchaSupport"))
        enable_captcha = from_union([from_bool, from_none], obj.get("enableCaptcha"))
        users = from_union([lambda x: from_list(UserElement.from_dict, x), from_none], obj.get("users"))
        return Local(allows_signup, captcha_support, enable_captcha, users)

    def to_dict(self) -> dict:
        result: dict = {}
        result["allowsSignup"] = from_union([from_bool, from_none], self.allows_signup)
        result["captchaSupport"] = from_union([lambda x: to_class(LocalCAPTCHASupport, x), from_none], self.captcha_support)
        result["enableCaptcha"] = from_union([from_bool, from_none], self.enable_captcha)
        result["users"] = from_union([lambda x: from_list(lambda x: to_class(UserElement, x), x), from_none], self.users)
        return result


@dataclass
class FluffyLog:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyLog':
        assert isinstance(obj, dict)
        return FluffyLog()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Logger:
    level: Optional[str] = None
    name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Logger':
        assert isinstance(obj, dict)
        level = from_union([from_str, from_none], obj.get("level"))
        name = from_union([from_str, from_none], obj.get("name"))
        return Logger(level, name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["level"] = from_union([from_str, from_none], self.level)
        result["name"] = from_union([from_str, from_none], self.name)
        return result


@dataclass
class LogRecorder:
    loggers: Optional[List[Logger]] = None
    name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'LogRecorder':
        assert isinstance(obj, dict)
        loggers = from_union([lambda x: from_list(Logger.from_dict, x), from_none], obj.get("loggers"))
        name = from_union([from_str, from_none], obj.get("name"))
        return LogRecorder(loggers, name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["loggers"] = from_union([lambda x: from_list(lambda x: to_class(Logger, x), x), from_none], self.loggers)
        result["name"] = from_union([from_str, from_none], self.name)
        return result


@dataclass
class LoggedInUsersCanDoAnything:
    """If checked, this will allow users who are not authenticated to access Jenkins in a
    read-only mode.
    """
    allow_anonymous_read: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'LoggedInUsersCanDoAnything':
        assert isinstance(obj, dict)
        allow_anonymous_read = from_union([from_bool, from_none], obj.get("allowAnonymousRead"))
        return LoggedInUsersCanDoAnything(allow_anonymous_read)

    def to_dict(self) -> dict:
        result: dict = {}
        result["allowAnonymousRead"] = from_union([from_bool, from_none], self.allow_anonymous_read)
        return result


@dataclass
class JenkinsMailer:
    email_address: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsMailer':
        assert isinstance(obj, dict)
        email_address = from_union([from_str, from_none], obj.get("emailAddress"))
        return JenkinsMailer(email_address)

    def to_dict(self) -> dict:
        result: dict = {}
        result["emailAddress"] = from_union([from_str, from_none], self.email_address)
        return result


@dataclass
class ManuallyProvidedKeyVerificationStrategy:
    """The SSH key expected for this connection. This key should be in the form `algorithm
    value` where algorithm is one of ssh-rsa or ssh-dss, and value is the Base 64 encoded
    content of the key.
    """
    key: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ManuallyProvidedKeyVerificationStrategy':
        assert isinstance(obj, dict)
        key = from_union([from_str, from_none], obj.get("key"))
        return ManuallyProvidedKeyVerificationStrategy(key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["key"] = from_union([from_str, from_none], self.key)
        return result


@dataclass
class ManuallyTrustedKeyVerificationStrategy:
    """Require a user with Computer.CONFIGURE permission to authorise the key presented during
    the first connection to this host before the connection will be allowed to be
    established.
    If this option is not enabled then the key presented on first connection for this host
    will be automatically trusted and allowed for all subsequent connections without any
    manual intervention.
    """
    require_initial_manual_trust: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ManuallyTrustedKeyVerificationStrategy':
        assert isinstance(obj, dict)
        require_initial_manual_trust = from_union([from_bool, from_none], obj.get("requireInitialManualTrust"))
        return ManuallyTrustedKeyVerificationStrategy(require_initial_manual_trust)

    def to_dict(self) -> dict:
        result: dict = {}
        result["requireInitialManualTrust"] = from_union([from_bool, from_none], self.require_initial_manual_trust)
        return result


@dataclass
class FluffyMarkupFormatter:
    raw_html: Any
    plain_text: Any

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyMarkupFormatter':
        assert isinstance(obj, dict)
        raw_html = obj.get("rawHtml")
        plain_text = obj.get("plainText")
        return FluffyMarkupFormatter(raw_html, plain_text)

    def to_dict(self) -> dict:
        result: dict = {}
        result["rawHtml"] = self.raw_html
        result["plainText"] = self.plain_text
        return result


@dataclass
class JenkinsMaven:
    id: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsMaven':
        assert isinstance(obj, dict)
        id = from_union([from_str, from_none], obj.get("id"))
        return JenkinsMaven(id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_union([from_str, from_none], self.id)
        return result


@dataclass
class JenkinsMyView:
    primary_view_name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsMyView':
        assert isinstance(obj, dict)
        primary_view_name = from_union([from_str, from_none], obj.get("primaryViewName"))
        return JenkinsMyView(primary_view_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["primaryViewName"] = from_union([from_str, from_none], self.primary_view_name)
        return result


@dataclass
class FluffyMyViewsTabBar:
    standard: Any

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyMyViewsTabBar':
        assert isinstance(obj, dict)
        standard = obj.get("standard")
        return FluffyMyViewsTabBar(standard)

    def to_dict(self) -> dict:
        result: dict = {}
        result["standard"] = self.standard
        return result


@dataclass
class PurpleNode:
    permanent: Any
    jenkins: Any

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleNode':
        assert isinstance(obj, dict)
        permanent = obj.get("permanent")
        jenkins = obj.get("jenkins")
        return PurpleNode(permanent, jenkins)

    def to_dict(self) -> dict:
        result: dict = {}
        result["permanent"] = self.permanent
        result["jenkins"] = self.jenkins
        return result


@dataclass
class FluffyNodeProperty:
    disable_deferred_wipeout: Any
    tool_location: Any
    env_vars: Any
    authorization_matrix: Any

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyNodeProperty':
        assert isinstance(obj, dict)
        disable_deferred_wipeout = obj.get("disableDeferredWipeout")
        tool_location = obj.get("toolLocation")
        env_vars = obj.get("envVars")
        authorization_matrix = obj.get("authorizationMatrix")
        return FluffyNodeProperty(disable_deferred_wipeout, tool_location, env_vars, authorization_matrix)

    def to_dict(self) -> dict:
        result: dict = {}
        result["disableDeferredWipeout"] = self.disable_deferred_wipeout
        result["toolLocation"] = self.tool_location
        result["envVars"] = self.env_vars
        result["authorizationMatrix"] = self.authorization_matrix
        return result


@dataclass
class NonInheriting:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'NonInheriting':
        assert isinstance(obj, dict)
        return NonInheriting()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class NonVerifyingKeyVerificationStrategy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'NonVerifyingKeyVerificationStrategy':
        assert isinstance(obj, dict)
        return NonVerifyingKeyVerificationStrategy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PamCAPTCHASupport:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PamCAPTCHASupport':
        assert isinstance(obj, dict)
        return PamCAPTCHASupport()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Pam:
    captcha_support: Optional[PamCAPTCHASupport] = None
    service_name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Pam':
        assert isinstance(obj, dict)
        captcha_support = from_union([PamCAPTCHASupport.from_dict, from_none], obj.get("captchaSupport"))
        service_name = from_union([from_str, from_none], obj.get("serviceName"))
        return Pam(captcha_support, service_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["captchaSupport"] = from_union([lambda x: to_class(PamCAPTCHASupport, x), from_none], self.captcha_support)
        result["serviceName"] = from_union([from_str, from_none], self.service_name)
        return result


@dataclass
class JenkinsPathSpecification:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2014, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    Select this option to require that the paths match taking character case into account.
    """
    case_sensitive: Optional[bool] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2014, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of excluded paths. (ANT style * and ** wildcards are permitted in
    paths,
    for example: /jenkins/github/*,/jenkins-ci/**/org,jenkinsci.github.io.)
    
    The empty list implies no paths are excluded. The excludes list is processed after the
    includes list.
    """
    excludes: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2014, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of included paths. (ANT style * and ** wildcards are permitted in
    paths,
    for example: /jenkins/github/*,/jenkins-ci/**/org,jenkinsci.github.io.)
    
    The empty list implies no paths are excluded. The excludes list is processed after the
    includes list.
    """
    includes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsPathSpecification':
        assert isinstance(obj, dict)
        case_sensitive = from_union([from_bool, from_none], obj.get("caseSensitive"))
        excludes = from_union([from_str, from_none], obj.get("excludes"))
        includes = from_union([from_str, from_none], obj.get("includes"))
        return JenkinsPathSpecification(case_sensitive, excludes, includes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["caseSensitive"] = from_union([from_bool, from_none], self.case_sensitive)
        result["excludes"] = from_union([from_str, from_none], self.excludes)
        result["includes"] = from_union([from_str, from_none], self.includes)
        return result


@dataclass
class Pattern:
    """Provide a human-readable description to explain naming constraints.
    This will be used as the error message when the job name does not match the pattern.
    """
    description: Optional[str] = None
    force_existing_jobs: Optional[bool] = None
    name_pattern: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Pattern':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        force_existing_jobs = from_union([from_bool, from_none], obj.get("forceExistingJobs"))
        name_pattern = from_union([from_str, from_none], obj.get("namePattern"))
        return Pattern(description, force_existing_jobs, name_pattern)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["forceExistingJobs"] = from_union([from_bool, from_none], self.force_existing_jobs)
        result["namePattern"] = from_union([from_str, from_none], self.name_pattern)
        return result


@dataclass
class Launcher:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Launcher':
        assert isinstance(obj, dict)
        return Launcher()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PermanentNodeProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PermanentNodeProperty':
        assert isinstance(obj, dict)
        return PermanentNodeProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PermanentRetentionStrategy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PermanentRetentionStrategy':
        assert isinstance(obj, dict)
        return PermanentRetentionStrategy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Permanent:
    label_string: Optional[str] = None
    launcher: Optional[Launcher] = None
    mode: Optional[Mode] = None
    name: Optional[str] = None
    node_description: Optional[str] = None
    node_name: Optional[str] = None
    node_properties: Optional[List[PermanentNodeProperty]] = None
    num_executors: Optional[int] = None
    remote_fs: Optional[str] = None
    retention_strategy: Optional[PermanentRetentionStrategy] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Permanent':
        assert isinstance(obj, dict)
        label_string = from_union([from_str, from_none], obj.get("labelString"))
        launcher = from_union([Launcher.from_dict, from_none], obj.get("launcher"))
        mode = from_union([Mode, from_none], obj.get("mode"))
        name = from_union([from_str, from_none], obj.get("name"))
        node_description = from_union([from_str, from_none], obj.get("nodeDescription"))
        node_name = from_union([from_str, from_none], obj.get("nodeName"))
        node_properties = from_union([lambda x: from_list(PermanentNodeProperty.from_dict, x), from_none], obj.get("nodeProperties"))
        num_executors = from_union([from_int, from_none], obj.get("numExecutors"))
        remote_fs = from_union([from_str, from_none], obj.get("remoteFS"))
        retention_strategy = from_union([PermanentRetentionStrategy.from_dict, from_none], obj.get("retentionStrategy"))
        return Permanent(label_string, launcher, mode, name, node_description, node_name, node_properties, num_executors, remote_fs, retention_strategy)

    def to_dict(self) -> dict:
        result: dict = {}
        result["labelString"] = from_union([from_str, from_none], self.label_string)
        result["launcher"] = from_union([lambda x: to_class(Launcher, x), from_none], self.launcher)
        result["mode"] = from_union([lambda x: to_enum(Mode, x), from_none], self.mode)
        result["name"] = from_union([from_str, from_none], self.name)
        result["nodeDescription"] = from_union([from_str, from_none], self.node_description)
        result["nodeName"] = from_union([from_str, from_none], self.node_name)
        result["nodeProperties"] = from_union([lambda x: from_list(lambda x: to_class(PermanentNodeProperty, x), x), from_none], self.node_properties)
        result["numExecutors"] = from_union([from_int, from_none], self.num_executors)
        result["remoteFS"] = from_union([from_str, from_none], self.remote_fs)
        result["retentionStrategy"] = from_union([lambda x: to_class(PermanentRetentionStrategy, x), from_none], self.retention_strategy)
        return result


@dataclass
class PlainText:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PlainText':
        assert isinstance(obj, dict)
        return PlainText()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PreferredProvider:
    """Allows the user to select their preferred user interface when clicking links to Jenkins
    from notifications (e.g. Email, Slack, or GitHub).
    """
    provider_id: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'PreferredProvider':
        assert isinstance(obj, dict)
        provider_id = from_union([from_str, from_none], obj.get("providerId"))
        return PreferredProvider(provider_id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["providerId"] = from_union([from_str, from_none], self.provider_id)
        return result


@dataclass
class JenkinsPrivateKeySource:
    direct_entry: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsPrivateKeySource':
        assert isinstance(obj, dict)
        direct_entry = obj.get("directEntry")
        return JenkinsPrivateKeySource(direct_entry)

    def to_dict(self) -> dict:
        result: dict = {}
        result["directEntry"] = self.direct_entry
        return result


@dataclass
class FluffyProjectNamingStrategy:
    standard: Any
    pattern: Any

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyProjectNamingStrategy':
        assert isinstance(obj, dict)
        standard = obj.get("standard")
        pattern = obj.get("pattern")
        return FluffyProjectNamingStrategy(standard, pattern)

    def to_dict(self) -> dict:
        result: dict = {}
        result["standard"] = self.standard
        result["pattern"] = self.pattern
        return result


@dataclass
class SecretPassword:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'SecretPassword':
        assert isinstance(obj, dict)
        return SecretPassword()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FluffyProxy:
    """If your Jenkins server sits behind a firewall and does not have the direct access to the
    internet,
    and if your server JVM is not configured appropriately
    (See JDK networking properties for more details)
    to enable internet connection, you can specify the HTTP proxy server name in this field
    to allow Jenkins
    to install plugins on behalf of you. Note that Jenkins uses HTTPS to communicate with the
    update center to download plugins.
    
    
    Leaving this field empty
    means Jenkins will try to connect to the internet directly.
    
    
    If you are unsure about the value, check the browser proxy configuration.
    """
    name: Optional[str] = None
    """Specify host name patterns that shouldn't go through the proxy, one host per line.
    "*" is the wild card host name (such as "*.jenkins.io" or "www*.jenkins-ci.org")
    """
    no_proxy_host: Optional[str] = None
    """This field works in conjunction with the proxy server field to specify the HTTP proxy
    port.
    """
    port: Optional[int] = None
    secret_password: Optional[SecretPassword] = None
    test_url: Optional[str] = None
    """This field works in conjunction with the proxy server field
    to specify the username used to authenticate with the proxy.
    
    
    If this proxy requires Microsofts NTLM
    authentication scheme then the domain name can be encoded
    within the username by prefixing the domain name followed
    by a back-slash '\' before the username, e.g "ACME\John Doo".
    """
    user_name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyProxy':
        assert isinstance(obj, dict)
        name = from_union([from_str, from_none], obj.get("name"))
        no_proxy_host = from_union([from_str, from_none], obj.get("noProxyHost"))
        port = from_union([from_int, from_none], obj.get("port"))
        secret_password = from_union([SecretPassword.from_dict, from_none], obj.get("secretPassword"))
        test_url = from_union([from_str, from_none], obj.get("testUrl"))
        user_name = from_union([from_str, from_none], obj.get("userName"))
        return FluffyProxy(name, no_proxy_host, port, secret_password, test_url, user_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_union([from_str, from_none], self.name)
        result["noProxyHost"] = from_union([from_str, from_none], self.no_proxy_host)
        result["port"] = from_union([from_int, from_none], self.port)
        result["secretPassword"] = from_union([lambda x: to_class(SecretPassword, x), from_none], self.secret_password)
        result["testUrl"] = from_union([from_str, from_none], self.test_url)
        result["userName"] = from_union([from_str, from_none], self.user_name)
        return result


@dataclass
class RawHTML:
    disable_syntax_highlighting: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'RawHTML':
        assert isinstance(obj, dict)
        disable_syntax_highlighting = from_union([from_bool, from_none], obj.get("disableSyntaxHighlighting"))
        return RawHTML(disable_syntax_highlighting)

    def to_dict(self) -> dict:
        result: dict = {}
        result["disableSyntaxHighlighting"] = from_union([from_bool, from_none], self.disable_syntax_highlighting)
        return result


@dataclass
class FluffyRemotingSecurity:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyRemotingSecurity':
        assert isinstance(obj, dict)
        return FluffyRemotingSecurity()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsRetentionStrategy:
    always: Any
    schedule: Any
    demand: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsRetentionStrategy':
        assert isinstance(obj, dict)
        always = obj.get("always")
        schedule = obj.get("schedule")
        demand = obj.get("demand")
        return JenkinsRetentionStrategy(always, schedule, demand)

    def to_dict(self) -> dict:
        result: dict = {}
        result["always"] = self.always
        result["schedule"] = self.schedule
        result["demand"] = self.demand
        return result


@dataclass
class Schedule:
    keep_up_when_active: Optional[bool] = None
    start_time_spec: Optional[str] = None
    up_time_mins: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Schedule':
        assert isinstance(obj, dict)
        keep_up_when_active = from_union([from_bool, from_none], obj.get("keepUpWhenActive"))
        start_time_spec = from_union([from_str, from_none], obj.get("startTimeSpec"))
        up_time_mins = from_union([from_int, from_none], obj.get("upTimeMins"))
        return Schedule(keep_up_when_active, start_time_spec, up_time_mins)

    def to_dict(self) -> dict:
        result: dict = {}
        result["keepUpWhenActive"] = from_union([from_bool, from_none], self.keep_up_when_active)
        result["startTimeSpec"] = from_union([from_str, from_none], self.start_time_spec)
        result["upTimeMins"] = from_union([from_int, from_none], self.up_time_mins)
        return result


@dataclass
class JenkinsSchemeSpecification:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2013, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    A comma separated list of URI schemes (as defined in RFC-3986).
    For example: http, https, ssh, sftp, imap.
    """
    schemes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsSchemeSpecification':
        assert isinstance(obj, dict)
        schemes = from_union([from_str, from_none], obj.get("schemes"))
        return JenkinsSchemeSpecification(schemes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["schemes"] = from_union([from_str, from_none], self.schemes)
        return result


@dataclass
class FluffySecurityRealm:
    legacy: Any
    none: Any
    pam: Any
    local: Any

    @staticmethod
    def from_dict(obj: Any) -> 'FluffySecurityRealm':
        assert isinstance(obj, dict)
        legacy = obj.get("legacy")
        none = obj.get("none")
        pam = obj.get("pam")
        local = obj.get("local")
        return FluffySecurityRealm(legacy, none, pam, local)

    def to_dict(self) -> dict:
        result: dict = {}
        result["legacy"] = self.legacy
        result["none"] = self.none
        result["pam"] = self.pam
        result["local"] = self.local
        return result


@dataclass
class SSHSSHHostKeyVerificationStrategy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'SSHSSHHostKeyVerificationStrategy':
        assert isinstance(obj, dict)
        return SSHSSHHostKeyVerificationStrategy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class SSH:
    credentials_id: Optional[str] = None
    host: Optional[str] = None
    java_path: Optional[str] = None
    jvm_options: Optional[str] = None
    launch_timeout_seconds: Optional[int] = None
    max_num_retries: Optional[int] = None
    port: Optional[int] = None
    prefix_start_slave_cmd: Optional[str] = None
    retry_wait_time: Optional[int] = None
    ssh_host_key_verification_strategy: Optional[SSHSSHHostKeyVerificationStrategy] = None
    suffix_start_slave_cmd: Optional[str] = None
    tcp_no_delay: Optional[bool] = None
    work_dir: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SSH':
        assert isinstance(obj, dict)
        credentials_id = from_union([from_str, from_none], obj.get("credentialsId"))
        host = from_union([from_str, from_none], obj.get("host"))
        java_path = from_union([from_str, from_none], obj.get("javaPath"))
        jvm_options = from_union([from_str, from_none], obj.get("jvmOptions"))
        launch_timeout_seconds = from_union([from_int, from_none], obj.get("launchTimeoutSeconds"))
        max_num_retries = from_union([from_int, from_none], obj.get("maxNumRetries"))
        port = from_union([from_int, from_none], obj.get("port"))
        prefix_start_slave_cmd = from_union([from_str, from_none], obj.get("prefixStartSlaveCmd"))
        retry_wait_time = from_union([from_int, from_none], obj.get("retryWaitTime"))
        ssh_host_key_verification_strategy = from_union([SSHSSHHostKeyVerificationStrategy.from_dict, from_none], obj.get("sshHostKeyVerificationStrategy"))
        suffix_start_slave_cmd = from_union([from_str, from_none], obj.get("suffixStartSlaveCmd"))
        tcp_no_delay = from_union([from_bool, from_none], obj.get("tcpNoDelay"))
        work_dir = from_union([from_str, from_none], obj.get("workDir"))
        return SSH(credentials_id, host, java_path, jvm_options, launch_timeout_seconds, max_num_retries, port, prefix_start_slave_cmd, retry_wait_time, ssh_host_key_verification_strategy, suffix_start_slave_cmd, tcp_no_delay, work_dir)

    def to_dict(self) -> dict:
        result: dict = {}
        result["credentialsId"] = from_union([from_str, from_none], self.credentials_id)
        result["host"] = from_union([from_str, from_none], self.host)
        result["javaPath"] = from_union([from_str, from_none], self.java_path)
        result["jvmOptions"] = from_union([from_str, from_none], self.jvm_options)
        result["launchTimeoutSeconds"] = from_union([from_int, from_none], self.launch_timeout_seconds)
        result["maxNumRetries"] = from_union([from_int, from_none], self.max_num_retries)
        result["port"] = from_union([from_int, from_none], self.port)
        result["prefixStartSlaveCmd"] = from_union([from_str, from_none], self.prefix_start_slave_cmd)
        result["retryWaitTime"] = from_union([from_int, from_none], self.retry_wait_time)
        result["sshHostKeyVerificationStrategy"] = from_union([lambda x: to_class(SSHSSHHostKeyVerificationStrategy, x), from_none], self.ssh_host_key_verification_strategy)
        result["suffixStartSlaveCmd"] = from_union([from_str, from_none], self.suffix_start_slave_cmd)
        result["tcpNoDelay"] = from_union([from_bool, from_none], self.tcp_no_delay)
        result["workDir"] = from_union([from_str, from_none], self.work_dir)
        return result


@dataclass
class JenkinsSSHHostKeyVerificationStrategy:
    manually_trusted_key_verification_strategy: Any
    manually_provided_key_verification_strategy: Any
    non_verifying_key_verification_strategy: Any
    known_hosts_file_key_verification_strategy: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsSSHHostKeyVerificationStrategy':
        assert isinstance(obj, dict)
        manually_trusted_key_verification_strategy = obj.get("manuallyTrustedKeyVerificationStrategy")
        manually_provided_key_verification_strategy = obj.get("manuallyProvidedKeyVerificationStrategy")
        non_verifying_key_verification_strategy = obj.get("nonVerifyingKeyVerificationStrategy")
        known_hosts_file_key_verification_strategy = obj.get("knownHostsFileKeyVerificationStrategy")
        return JenkinsSSHHostKeyVerificationStrategy(manually_trusted_key_verification_strategy, manually_provided_key_verification_strategy, non_verifying_key_verification_strategy, known_hosts_file_key_verification_strategy)

    def to_dict(self) -> dict:
        result: dict = {}
        result["manuallyTrustedKeyVerificationStrategy"] = self.manually_trusted_key_verification_strategy
        result["manuallyProvidedKeyVerificationStrategy"] = self.manually_provided_key_verification_strategy
        result["nonVerifyingKeyVerificationStrategy"] = self.non_verifying_key_verification_strategy
        result["knownHostsFileKeyVerificationStrategy"] = self.known_hosts_file_key_verification_strategy
        return result


@dataclass
class SSHPublicKey:
    """List SSH public keys that are associated with the user account.
    These keys can be used for example by Jenkins CLI.
    """
    authorized_keys: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SSHPublicKey':
        assert isinstance(obj, dict)
        authorized_keys = from_union([from_str, from_none], obj.get("authorizedKeys"))
        return SSHPublicKey(authorized_keys)

    def to_dict(self) -> dict:
        result: dict = {}
        result["authorizedKeys"] = from_union([from_str, from_none], self.authorized_keys)
        return result


@dataclass
class JenkinsStandard:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsStandard':
        assert isinstance(obj, dict)
        return JenkinsStandard()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Status:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Status':
        assert isinstance(obj, dict)
        return Status()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class StatusFilter:
    status_filter: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'StatusFilter':
        assert isinstance(obj, dict)
        status_filter = from_union([from_bool, from_none], obj.get("statusFilter"))
        return StatusFilter(status_filter)

    def to_dict(self) -> dict:
        result: dict = {}
        result["statusFilter"] = from_union([from_bool, from_none], self.status_filter)
        return result


@dataclass
class FluffySecret:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffySecret':
        assert isinstance(obj, dict)
        return FluffySecret()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsString:
    description: Optional[str] = None
    id: Optional[str] = None
    scope: Optional[Scope] = None
    secret: Optional[FluffySecret] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsString':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        secret = from_union([FluffySecret.from_dict, from_none], obj.get("secret"))
        return JenkinsString(description, id, scope, secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        result["secret"] = from_union([lambda x: to_class(FluffySecret, x), from_none], self.secret)
        return result


@dataclass
class Target:
    level: Optional[str] = None
    name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Target':
        assert isinstance(obj, dict)
        level = from_union([from_str, from_none], obj.get("level"))
        name = from_union([from_str, from_none], obj.get("name"))
        return Target(level, name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["level"] = from_union([from_str, from_none], self.level)
        result["name"] = from_union([from_str, from_none], self.name)
        return result


@dataclass
class Timezone:
    """Specify user defined time zone for displaying time rather than system default."""
    time_zone_name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Timezone':
        assert isinstance(obj, dict)
        time_zone_name = from_union([from_str, from_none], obj.get("timeZoneName"))
        return Timezone(time_zone_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["timeZoneName"] = from_union([from_str, from_none], self.time_zone_name)
        return result


@dataclass
class JenkinsToolInstaller:
    zip: Any
    batch_file: Any
    jdk_installer: Any
    maven: Any
    command: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsToolInstaller':
        assert isinstance(obj, dict)
        zip = obj.get("zip")
        batch_file = obj.get("batchFile")
        jdk_installer = obj.get("jdkInstaller")
        maven = obj.get("maven")
        command = obj.get("command")
        return JenkinsToolInstaller(zip, batch_file, jdk_installer, maven, command)

    def to_dict(self) -> dict:
        result: dict = {}
        result["zip"] = self.zip
        result["batchFile"] = self.batch_file
        result["jdkInstaller"] = self.jdk_installer
        result["maven"] = self.maven
        result["command"] = self.command
        return result


@dataclass
class ToolLocation:
    home: Optional[str] = None
    key: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ToolLocation':
        assert isinstance(obj, dict)
        home = from_union([from_str, from_none], obj.get("home"))
        key = from_union([from_str, from_none], obj.get("key"))
        return ToolLocation(home, key)

    def to_dict(self) -> dict:
        result: dict = {}
        result["home"] = from_union([from_str, from_none], self.home)
        result["key"] = from_union([from_str, from_none], self.key)
        return result


@dataclass
class JenkinsToolProperty:
    install_source: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsToolProperty':
        assert isinstance(obj, dict)
        install_source = obj.get("installSource")
        return JenkinsToolProperty(install_source)

    def to_dict(self) -> dict:
        result: dict = {}
        result["installSource"] = self.install_source
        return result


@dataclass
class Unsecured:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Unsecured':
        assert isinstance(obj, dict)
        return Unsecured()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FluffyUpdateCenter:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyUpdateCenter':
        assert isinstance(obj, dict)
        return FluffyUpdateCenter()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UpdateSite:
    id: Optional[str] = None
    url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'UpdateSite':
        assert isinstance(obj, dict)
        id = from_union([from_str, from_none], obj.get("id"))
        url = from_union([from_str, from_none], obj.get("url"))
        return UpdateSite(id, url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_union([from_str, from_none], self.id)
        result["url"] = from_union([from_str, from_none], self.url)
        return result


@dataclass
class FluffyUploadedKeystore:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyUploadedKeystore':
        assert isinstance(obj, dict)
        return FluffyUploadedKeystore()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsUploaded:
    uploaded_keystore: Optional[FluffyUploadedKeystore] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsUploaded':
        assert isinstance(obj, dict)
        uploaded_keystore = from_union([FluffyUploadedKeystore.from_dict, from_none], obj.get("uploadedKeystore"))
        return JenkinsUploaded(uploaded_keystore)

    def to_dict(self) -> dict:
        result: dict = {}
        result["uploadedKeystore"] = from_union([lambda x: to_class(FluffyUploadedKeystore, x), from_none], self.uploaded_keystore)
        return result


@dataclass
class UserProperty:
    last_granted_authorities: Any
    ssh_public_key: Any
    user_seed: Any
    search: Any
    pane_status: Any
    password: Any
    my_view: Any
    api_token: Any
    timezone: Any
    mailer: Any
    user_credentials_property: Any
    preferred_provider: Any

    @staticmethod
    def from_dict(obj: Any) -> 'UserProperty':
        assert isinstance(obj, dict)
        last_granted_authorities = obj.get("lastGrantedAuthorities")
        ssh_public_key = obj.get("sshPublicKey")
        user_seed = obj.get("userSeed")
        search = obj.get("search")
        pane_status = obj.get("paneStatus")
        password = obj.get("password")
        my_view = obj.get("myView")
        api_token = obj.get("apiToken")
        timezone = obj.get("timezone")
        mailer = obj.get("mailer")
        user_credentials_property = obj.get("userCredentialsProperty")
        preferred_provider = obj.get("preferredProvider")
        return UserProperty(last_granted_authorities, ssh_public_key, user_seed, search, pane_status, password, my_view, api_token, timezone, mailer, user_credentials_property, preferred_provider)

    def to_dict(self) -> dict:
        result: dict = {}
        result["lastGrantedAuthorities"] = self.last_granted_authorities
        result["sshPublicKey"] = self.ssh_public_key
        result["userSeed"] = self.user_seed
        result["search"] = self.search
        result["paneStatus"] = self.pane_status
        result["password"] = self.password
        result["myView"] = self.my_view
        result["apiToken"] = self.api_token
        result["timezone"] = self.timezone
        result["mailer"] = self.mailer
        result["userCredentialsProperty"] = self.user_credentials_property
        result["preferredProvider"] = self.preferred_provider
        return result


@dataclass
class UserWithPasswordProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UserWithPasswordProperty':
        assert isinstance(obj, dict)
        return UserWithPasswordProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UserWithPassword:
    description: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None
    password: Optional[str] = None
    properties: Optional[List[UserWithPasswordProperty]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'UserWithPassword':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        name = from_union([from_str, from_none], obj.get("name"))
        password = from_union([from_str, from_none], obj.get("password"))
        properties = from_union([lambda x: from_list(UserWithPasswordProperty.from_dict, x), from_none], obj.get("properties"))
        return UserWithPassword(description, id, name, password, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["name"] = from_union([from_str, from_none], self.name)
        result["password"] = from_union([from_str, from_none], self.password)
        result["properties"] = from_union([lambda x: from_list(lambda x: to_class(UserWithPasswordProperty, x), x), from_none], self.properties)
        return result


@dataclass
class JenkinsUsernamePassword:
    description: Optional[str] = None
    id: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The password.
    """
    password: Optional[str] = None
    scope: Optional[Scope] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    
    The username.
    """
    username: Optional[str] = None
    """Historically, not only passwords but usernames were masked in the build log.
    Since these can interfere with diagnostics,
    and cause unrelated occurrences of a common word to be masked,
    you may choose to leave usernames unmasked if they are not sensitive.
    Note that regardless of this setting, the username will be displayed to anyone permitted
    to reconfigure the credentials.
    """
    username_secret: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsUsernamePassword':
        assert isinstance(obj, dict)
        description = from_union([from_str, from_none], obj.get("description"))
        id = from_union([from_str, from_none], obj.get("id"))
        password = from_union([from_str, from_none], obj.get("password"))
        scope = from_union([Scope, from_none], obj.get("scope"))
        username = from_union([from_str, from_none], obj.get("username"))
        username_secret = from_union([from_bool, from_none], obj.get("usernameSecret"))
        return JenkinsUsernamePassword(description, id, password, scope, username, username_secret)

    def to_dict(self) -> dict:
        result: dict = {}
        result["description"] = from_union([from_str, from_none], self.description)
        result["id"] = from_union([from_str, from_none], self.id)
        result["password"] = from_union([from_str, from_none], self.password)
        result["scope"] = from_union([lambda x: to_enum(Scope, x), from_none], self.scope)
        result["username"] = from_union([from_str, from_none], self.username)
        result["usernameSecret"] = from_union([from_bool, from_none], self.username_secret)
        return result


@dataclass
class PurpleView:
    empty: Any
    all: Any
    proxy: Any
    my_view: Any
    list: Any

    @staticmethod
    def from_dict(obj: Any) -> 'PurpleView':
        assert isinstance(obj, dict)
        empty = obj.get("")
        all = obj.get("all")
        proxy = obj.get("proxy")
        my_view = obj.get("myView")
        list = obj.get("list")
        return PurpleView(empty, all, proxy, my_view, list)

    def to_dict(self) -> dict:
        result: dict = {}
        result[""] = self.empty
        result["all"] = self.all
        result["proxy"] = self.proxy
        result["myView"] = self.my_view
        result["list"] = self.list
        return result


@dataclass
class ViewJobFilter:
    status_filter: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ViewJobFilter':
        assert isinstance(obj, dict)
        status_filter = obj.get("statusFilter")
        return ViewJobFilter(status_filter)

    def to_dict(self) -> dict:
        result: dict = {}
        result["statusFilter"] = self.status_filter
        return result


@dataclass
class FluffyViewsTabBar:
    standard: Any

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyViewsTabBar':
        assert isinstance(obj, dict)
        standard = obj.get("standard")
        return FluffyViewsTabBar(standard)

    def to_dict(self) -> dict:
        result: dict = {}
        result["standard"] = self.standard
        return result


@dataclass
class Weather:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Weather':
        assert isinstance(obj, dict)
        return Weather()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JenkinsZip:
    label: Optional[str] = None
    """Optional subdirectory of the downloaded and unpacked archive to use as the tool's home
    directory.
    """
    subdir: Optional[str] = None
    """URL from which to download the tool in binary form.
    Should be either a ZIP or a GZip-compressed TAR file.
    The timestamp on the server will be compared to the local version (if any)
    so you can publish updates easily.
    The URL must be accessible from the Jenkins controller but need not be accessible from
    agents.
    """
    url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'JenkinsZip':
        assert isinstance(obj, dict)
        label = from_union([from_str, from_none], obj.get("label"))
        subdir = from_union([from_str, from_none], obj.get("subdir"))
        url = from_union([from_str, from_none], obj.get("url"))
        return JenkinsZip(label, subdir, url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["label"] = from_union([from_str, from_none], self.label)
        result["subdir"] = from_union([from_str, from_none], self.subdir)
        result["url"] = from_union([from_str, from_none], self.url)
        return result


@dataclass
class ConfigurationBaseForTheJenkinsClassifier:
    captcha_support: Any
    cloud: Any
    label_atom_property: Any
    empty: Optional[Jenkins] = None
    agent_protocols: Optional[str] = None
    all: Optional[All] = None
    always: Optional[Always] = None
    api_token: Optional[JenkinsAPIToken] = None
    authorization_matrix_node_property: Optional[AuthorizationMatrixNodeProperty] = None
    authorization_strategy: Optional[PurpleAuthorizationStrategy] = None
    basic_ssh_user_private_key: Optional[JenkinsBasicSSHUserPrivateKey] = None
    batch_file: Optional[JenkinsBatchFile] = None
    branch_status_column: Optional[BranchStatusColumn] = None
    build_button: Optional[BuildButton] = None
    certificate: Optional[JenkinsCertificate] = None
    command: Optional[JenkinsCommand] = None
    computer_launcher: Optional[ComputerLauncher] = None
    credentials: Optional[JenkinsCredentials] = None
    crumb_issuer: Optional[PurpleCrumbIssuer] = None
    demand: Optional[Demand] = None
    description_column: Optional[DescriptionColumn] = None
    direct_entry: Optional[JenkinsDirectEntry] = None
    disabled_administrative_monitors: Optional[str] = None
    disable_remember_me: Optional[bool] = None
    domain: Optional[JenkinsDomain] = None
    domain_credentials: Optional[JenkinsDomainCredentials] = None
    domain_specification: Optional[JenkinsDomainSpecification] = None
    entry: Optional[Entry] = None
    file: Optional[JenkinsFile] = None
    git_branch_specifier_column: Optional[GitBranchSpecifierColumn] = None
    hostname_port_specification: Optional[JenkinsHostnamePortSpecification] = None
    hostname_specification: Optional[JenkinsHostnameSpecification] = None
    inheritance_strategy: Optional[JenkinsInheritanceStrategy] = None
    inheriting: Optional[Inheriting] = None
    inheriting_global: Optional[InheritingGlobal] = None
    item_column: Optional[ItemColumn] = None
    jdk: Optional[JenkinsJDK] = None
    jdk_installer: Optional[JenkinsJDKInstaller] = None
    j_d_ks: Optional[JDKs] = None
    jenkins: Optional[JenkinsClass] = None
    jnlp: Optional[Jnlp] = None
    job_name: Optional[JobName] = None
    key_store_source: Optional[JenkinsKeyStoreSource] = None
    known_hosts_file_key_verification_strategy: Optional[KnownHostsFileKeyVerificationStrategy] = None
    label_atom: Optional[PurpleLabelAtom] = None
    label_atoms: Optional[LabelAtoms] = None
    label_string: Optional[str] = None
    last_duration: Optional[LastDuration] = None
    last_failure: Optional[LastFailure] = None
    last_stable: Optional[LastStable] = None
    last_success: Optional[LastSuccess] = None
    legacy: Optional[Legacy] = None
    list: Optional[ListClass] = None
    list_view_column: Optional[ListViewColumn] = None
    local: Optional[Local] = None
    log: Optional[FluffyLog] = None
    logged_in_users_can_do_anything: Optional[LoggedInUsersCanDoAnything] = None
    log_recorder: Optional[LogRecorder] = None
    mailer: Optional[JenkinsMailer] = None
    manually_provided_key_verification_strategy: Optional[ManuallyProvidedKeyVerificationStrategy] = None
    manually_trusted_key_verification_strategy: Optional[ManuallyTrustedKeyVerificationStrategy] = None
    markup_formatter: Optional[FluffyMarkupFormatter] = None
    maven: Optional[JenkinsMaven] = None
    mode: Optional[Mode] = None
    my_view: Optional[JenkinsMyView] = None
    my_views_tab_bar: Optional[FluffyMyViewsTabBar] = None
    node: Optional[PurpleNode] = None
    node_name: Optional[str] = None
    node_property: Optional[FluffyNodeProperty] = None
    non_inheriting: Optional[NonInheriting] = None
    non_verifying_key_verification_strategy: Optional[NonVerifyingKeyVerificationStrategy] = None
    no_usage_statistics: Optional[bool] = None
    num_executors: Optional[int] = None
    pam: Optional[Pam] = None
    path_specification: Optional[JenkinsPathSpecification] = None
    pattern: Optional[Pattern] = None
    permanent: Optional[Permanent] = None
    plain_text: Optional[PlainText] = None
    preferred_provider: Optional[PreferredProvider] = None
    private_key_source: Optional[JenkinsPrivateKeySource] = None
    project_naming_strategy: Optional[FluffyProjectNamingStrategy] = None
    proxy: Optional[FluffyProxy] = None
    quiet_period: Optional[int] = None
    raw_builds_dir: Optional[str] = None
    raw_html: Optional[RawHTML] = None
    remoting_security: Optional[FluffyRemotingSecurity] = None
    retention_strategy: Optional[JenkinsRetentionStrategy] = None
    schedule: Optional[Schedule] = None
    scheme_specification: Optional[JenkinsSchemeSpecification] = None
    scm_checkout_retry_count: Optional[int] = None
    security_realm: Optional[FluffySecurityRealm] = None
    slave_agent_port: Optional[int] = None
    ssh: Optional[SSH] = None
    ssh_host_key_verification_strategy: Optional[JenkinsSSHHostKeyVerificationStrategy] = None
    ssh_public_key: Optional[SSHPublicKey] = None
    standard: Optional[JenkinsStandard] = None
    status: Optional[Status] = None
    status_filter: Optional[StatusFilter] = None
    string: Optional[JenkinsString] = None
    system_message: Optional[str] = None
    target: Optional[Target] = None
    timezone: Optional[Timezone] = None
    tool_installer: Optional[JenkinsToolInstaller] = None
    tool_location: Optional[ToolLocation] = None
    tool_property: Optional[JenkinsToolProperty] = None
    unsecured: Optional[Unsecured] = None
    update_center: Optional[FluffyUpdateCenter] = None
    update_site: Optional[UpdateSite] = None
    uploaded: Optional[JenkinsUploaded] = None
    username_password: Optional[JenkinsUsernamePassword] = None
    user_property: Optional[UserProperty] = None
    user_with_password: Optional[UserWithPassword] = None
    view: Optional[PurpleView] = None
    view_job_filter: Optional[ViewJobFilter] = None
    views_tab_bar: Optional[FluffyViewsTabBar] = None
    weather: Optional[Weather] = None
    zip: Optional[JenkinsZip] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ConfigurationBaseForTheJenkinsClassifier':
        assert isinstance(obj, dict)
        captcha_support = obj.get("captchaSupport")
        cloud = obj.get("cloud")
        label_atom_property = obj.get("labelAtomProperty")
        empty = from_union([Jenkins.from_dict, from_none], obj.get(""))
        agent_protocols = from_union([from_str, from_none], obj.get("agentProtocols"))
        all = from_union([All.from_dict, from_none], obj.get("all"))
        always = from_union([Always.from_dict, from_none], obj.get("always"))
        api_token = from_union([JenkinsAPIToken.from_dict, from_none], obj.get("apiToken"))
        authorization_matrix_node_property = from_union([AuthorizationMatrixNodeProperty.from_dict, from_none], obj.get("authorizationMatrixNodeProperty"))
        authorization_strategy = from_union([PurpleAuthorizationStrategy.from_dict, from_none], obj.get("authorizationStrategy"))
        basic_ssh_user_private_key = from_union([JenkinsBasicSSHUserPrivateKey.from_dict, from_none], obj.get("basicSSHUserPrivateKey"))
        batch_file = from_union([JenkinsBatchFile.from_dict, from_none], obj.get("batchFile"))
        branch_status_column = from_union([BranchStatusColumn.from_dict, from_none], obj.get("branchStatusColumn"))
        build_button = from_union([BuildButton.from_dict, from_none], obj.get("buildButton"))
        certificate = from_union([JenkinsCertificate.from_dict, from_none], obj.get("certificate"))
        command = from_union([JenkinsCommand.from_dict, from_none], obj.get("command"))
        computer_launcher = from_union([ComputerLauncher.from_dict, from_none], obj.get("computerLauncher"))
        credentials = from_union([JenkinsCredentials.from_dict, from_none], obj.get("credentials"))
        crumb_issuer = from_union([PurpleCrumbIssuer.from_dict, from_none], obj.get("crumbIssuer"))
        demand = from_union([Demand.from_dict, from_none], obj.get("demand"))
        description_column = from_union([DescriptionColumn.from_dict, from_none], obj.get("descriptionColumn"))
        direct_entry = from_union([JenkinsDirectEntry.from_dict, from_none], obj.get("directEntry"))
        disabled_administrative_monitors = from_union([from_str, from_none], obj.get("disabledAdministrativeMonitors"))
        disable_remember_me = from_union([from_bool, from_none], obj.get("disableRememberMe"))
        domain = from_union([JenkinsDomain.from_dict, from_none], obj.get("domain"))
        domain_credentials = from_union([JenkinsDomainCredentials.from_dict, from_none], obj.get("domainCredentials"))
        domain_specification = from_union([JenkinsDomainSpecification.from_dict, from_none], obj.get("domainSpecification"))
        entry = from_union([Entry.from_dict, from_none], obj.get("entry"))
        file = from_union([JenkinsFile.from_dict, from_none], obj.get("file"))
        git_branch_specifier_column = from_union([GitBranchSpecifierColumn.from_dict, from_none], obj.get("gitBranchSpecifierColumn"))
        hostname_port_specification = from_union([JenkinsHostnamePortSpecification.from_dict, from_none], obj.get("hostnamePortSpecification"))
        hostname_specification = from_union([JenkinsHostnameSpecification.from_dict, from_none], obj.get("hostnameSpecification"))
        inheritance_strategy = from_union([JenkinsInheritanceStrategy.from_dict, from_none], obj.get("inheritanceStrategy"))
        inheriting = from_union([Inheriting.from_dict, from_none], obj.get("inheriting"))
        inheriting_global = from_union([InheritingGlobal.from_dict, from_none], obj.get("inheritingGlobal"))
        item_column = from_union([ItemColumn.from_dict, from_none], obj.get("itemColumn"))
        jdk = from_union([JenkinsJDK.from_dict, from_none], obj.get("jdk"))
        jdk_installer = from_union([JenkinsJDKInstaller.from_dict, from_none], obj.get("jdkInstaller"))
        j_d_ks = from_union([JDKs.from_dict, from_none], obj.get("jDKs"))
        jenkins = from_union([JenkinsClass.from_dict, from_none], obj.get("jenkins"))
        jnlp = from_union([Jnlp.from_dict, from_none], obj.get("jnlp"))
        job_name = from_union([JobName.from_dict, from_none], obj.get("jobName"))
        key_store_source = from_union([JenkinsKeyStoreSource.from_dict, from_none], obj.get("keyStoreSource"))
        known_hosts_file_key_verification_strategy = from_union([KnownHostsFileKeyVerificationStrategy.from_dict, from_none], obj.get("knownHostsFileKeyVerificationStrategy"))
        label_atom = from_union([PurpleLabelAtom.from_dict, from_none], obj.get("labelAtom"))
        label_atoms = from_union([LabelAtoms.from_dict, from_none], obj.get("labelAtoms"))
        label_string = from_union([from_str, from_none], obj.get("labelString"))
        last_duration = from_union([LastDuration.from_dict, from_none], obj.get("lastDuration"))
        last_failure = from_union([LastFailure.from_dict, from_none], obj.get("lastFailure"))
        last_stable = from_union([LastStable.from_dict, from_none], obj.get("lastStable"))
        last_success = from_union([LastSuccess.from_dict, from_none], obj.get("lastSuccess"))
        legacy = from_union([Legacy.from_dict, from_none], obj.get("legacy"))
        list = from_union([ListClass.from_dict, from_none], obj.get("list"))
        list_view_column = from_union([ListViewColumn.from_dict, from_none], obj.get("listViewColumn"))
        local = from_union([Local.from_dict, from_none], obj.get("local"))
        log = from_union([FluffyLog.from_dict, from_none], obj.get("log"))
        logged_in_users_can_do_anything = from_union([LoggedInUsersCanDoAnything.from_dict, from_none], obj.get("loggedInUsersCanDoAnything"))
        log_recorder = from_union([LogRecorder.from_dict, from_none], obj.get("logRecorder"))
        mailer = from_union([JenkinsMailer.from_dict, from_none], obj.get("mailer"))
        manually_provided_key_verification_strategy = from_union([ManuallyProvidedKeyVerificationStrategy.from_dict, from_none], obj.get("manuallyProvidedKeyVerificationStrategy"))
        manually_trusted_key_verification_strategy = from_union([ManuallyTrustedKeyVerificationStrategy.from_dict, from_none], obj.get("manuallyTrustedKeyVerificationStrategy"))
        markup_formatter = from_union([FluffyMarkupFormatter.from_dict, from_none], obj.get("markupFormatter"))
        maven = from_union([JenkinsMaven.from_dict, from_none], obj.get("maven"))
        mode = from_union([Mode, from_none], obj.get("mode"))
        my_view = from_union([JenkinsMyView.from_dict, from_none], obj.get("myView"))
        my_views_tab_bar = from_union([FluffyMyViewsTabBar.from_dict, from_none], obj.get("myViewsTabBar"))
        node = from_union([PurpleNode.from_dict, from_none], obj.get("node"))
        node_name = from_union([from_str, from_none], obj.get("nodeName"))
        node_property = from_union([FluffyNodeProperty.from_dict, from_none], obj.get("nodeProperty"))
        non_inheriting = from_union([NonInheriting.from_dict, from_none], obj.get("nonInheriting"))
        non_verifying_key_verification_strategy = from_union([NonVerifyingKeyVerificationStrategy.from_dict, from_none], obj.get("nonVerifyingKeyVerificationStrategy"))
        no_usage_statistics = from_union([from_bool, from_none], obj.get("noUsageStatistics"))
        num_executors = from_union([from_int, from_none], obj.get("numExecutors"))
        pam = from_union([Pam.from_dict, from_none], obj.get("pam"))
        path_specification = from_union([JenkinsPathSpecification.from_dict, from_none], obj.get("pathSpecification"))
        pattern = from_union([Pattern.from_dict, from_none], obj.get("pattern"))
        permanent = from_union([Permanent.from_dict, from_none], obj.get("permanent"))
        plain_text = from_union([PlainText.from_dict, from_none], obj.get("plainText"))
        preferred_provider = from_union([PreferredProvider.from_dict, from_none], obj.get("preferredProvider"))
        private_key_source = from_union([JenkinsPrivateKeySource.from_dict, from_none], obj.get("privateKeySource"))
        project_naming_strategy = from_union([FluffyProjectNamingStrategy.from_dict, from_none], obj.get("projectNamingStrategy"))
        proxy = from_union([FluffyProxy.from_dict, from_none], obj.get("proxy"))
        quiet_period = from_union([from_int, from_none], obj.get("quietPeriod"))
        raw_builds_dir = from_union([from_str, from_none], obj.get("rawBuildsDir"))
        raw_html = from_union([RawHTML.from_dict, from_none], obj.get("rawHtml"))
        remoting_security = from_union([FluffyRemotingSecurity.from_dict, from_none], obj.get("remotingSecurity"))
        retention_strategy = from_union([JenkinsRetentionStrategy.from_dict, from_none], obj.get("retentionStrategy"))
        schedule = from_union([Schedule.from_dict, from_none], obj.get("schedule"))
        scheme_specification = from_union([JenkinsSchemeSpecification.from_dict, from_none], obj.get("schemeSpecification"))
        scm_checkout_retry_count = from_union([from_int, from_none], obj.get("scmCheckoutRetryCount"))
        security_realm = from_union([FluffySecurityRealm.from_dict, from_none], obj.get("securityRealm"))
        slave_agent_port = from_union([from_int, from_none], obj.get("slaveAgentPort"))
        ssh = from_union([SSH.from_dict, from_none], obj.get("ssh"))
        ssh_host_key_verification_strategy = from_union([JenkinsSSHHostKeyVerificationStrategy.from_dict, from_none], obj.get("sshHostKeyVerificationStrategy"))
        ssh_public_key = from_union([SSHPublicKey.from_dict, from_none], obj.get("sshPublicKey"))
        standard = from_union([JenkinsStandard.from_dict, from_none], obj.get("standard"))
        status = from_union([Status.from_dict, from_none], obj.get("status"))
        status_filter = from_union([StatusFilter.from_dict, from_none], obj.get("statusFilter"))
        string = from_union([JenkinsString.from_dict, from_none], obj.get("string"))
        system_message = from_union([from_str, from_none], obj.get("systemMessage"))
        target = from_union([Target.from_dict, from_none], obj.get("target"))
        timezone = from_union([Timezone.from_dict, from_none], obj.get("timezone"))
        tool_installer = from_union([JenkinsToolInstaller.from_dict, from_none], obj.get("toolInstaller"))
        tool_location = from_union([ToolLocation.from_dict, from_none], obj.get("toolLocation"))
        tool_property = from_union([JenkinsToolProperty.from_dict, from_none], obj.get("toolProperty"))
        unsecured = from_union([Unsecured.from_dict, from_none], obj.get("unsecured"))
        update_center = from_union([FluffyUpdateCenter.from_dict, from_none], obj.get("updateCenter"))
        update_site = from_union([UpdateSite.from_dict, from_none], obj.get("updateSite"))
        uploaded = from_union([JenkinsUploaded.from_dict, from_none], obj.get("uploaded"))
        username_password = from_union([JenkinsUsernamePassword.from_dict, from_none], obj.get("usernamePassword"))
        user_property = from_union([UserProperty.from_dict, from_none], obj.get("userProperty"))
        user_with_password = from_union([UserWithPassword.from_dict, from_none], obj.get("userWithPassword"))
        view = from_union([PurpleView.from_dict, from_none], obj.get("view"))
        view_job_filter = from_union([ViewJobFilter.from_dict, from_none], obj.get("viewJobFilter"))
        views_tab_bar = from_union([FluffyViewsTabBar.from_dict, from_none], obj.get("viewsTabBar"))
        weather = from_union([Weather.from_dict, from_none], obj.get("weather"))
        zip = from_union([JenkinsZip.from_dict, from_none], obj.get("zip"))
        return ConfigurationBaseForTheJenkinsClassifier(captcha_support, cloud, label_atom_property, empty, agent_protocols, all, always, api_token, authorization_matrix_node_property, authorization_strategy, basic_ssh_user_private_key, batch_file, branch_status_column, build_button, certificate, command, computer_launcher, credentials, crumb_issuer, demand, description_column, direct_entry, disabled_administrative_monitors, disable_remember_me, domain, domain_credentials, domain_specification, entry, file, git_branch_specifier_column, hostname_port_specification, hostname_specification, inheritance_strategy, inheriting, inheriting_global, item_column, jdk, jdk_installer, j_d_ks, jenkins, jnlp, job_name, key_store_source, known_hosts_file_key_verification_strategy, label_atom, label_atoms, label_string, last_duration, last_failure, last_stable, last_success, legacy, list, list_view_column, local, log, logged_in_users_can_do_anything, log_recorder, mailer, manually_provided_key_verification_strategy, manually_trusted_key_verification_strategy, markup_formatter, maven, mode, my_view, my_views_tab_bar, node, node_name, node_property, non_inheriting, non_verifying_key_verification_strategy, no_usage_statistics, num_executors, pam, path_specification, pattern, permanent, plain_text, preferred_provider, private_key_source, project_naming_strategy, proxy, quiet_period, raw_builds_dir, raw_html, remoting_security, retention_strategy, schedule, scheme_specification, scm_checkout_retry_count, security_realm, slave_agent_port, ssh, ssh_host_key_verification_strategy, ssh_public_key, standard, status, status_filter, string, system_message, target, timezone, tool_installer, tool_location, tool_property, unsecured, update_center, update_site, uploaded, username_password, user_property, user_with_password, view, view_job_filter, views_tab_bar, weather, zip)

    def to_dict(self) -> dict:
        result: dict = {}
        result["captchaSupport"] = self.captcha_support
        result["cloud"] = self.cloud
        result["labelAtomProperty"] = self.label_atom_property
        result[""] = from_union([lambda x: to_class(Jenkins, x), from_none], self.empty)
        result["agentProtocols"] = from_union([from_str, from_none], self.agent_protocols)
        result["all"] = from_union([lambda x: to_class(All, x), from_none], self.all)
        result["always"] = from_union([lambda x: to_class(Always, x), from_none], self.always)
        result["apiToken"] = from_union([lambda x: to_class(JenkinsAPIToken, x), from_none], self.api_token)
        result["authorizationMatrixNodeProperty"] = from_union([lambda x: to_class(AuthorizationMatrixNodeProperty, x), from_none], self.authorization_matrix_node_property)
        result["authorizationStrategy"] = from_union([lambda x: to_class(PurpleAuthorizationStrategy, x), from_none], self.authorization_strategy)
        result["basicSSHUserPrivateKey"] = from_union([lambda x: to_class(JenkinsBasicSSHUserPrivateKey, x), from_none], self.basic_ssh_user_private_key)
        result["batchFile"] = from_union([lambda x: to_class(JenkinsBatchFile, x), from_none], self.batch_file)
        result["branchStatusColumn"] = from_union([lambda x: to_class(BranchStatusColumn, x), from_none], self.branch_status_column)
        result["buildButton"] = from_union([lambda x: to_class(BuildButton, x), from_none], self.build_button)
        result["certificate"] = from_union([lambda x: to_class(JenkinsCertificate, x), from_none], self.certificate)
        result["command"] = from_union([lambda x: to_class(JenkinsCommand, x), from_none], self.command)
        result["computerLauncher"] = from_union([lambda x: to_class(ComputerLauncher, x), from_none], self.computer_launcher)
        result["credentials"] = from_union([lambda x: to_class(JenkinsCredentials, x), from_none], self.credentials)
        result["crumbIssuer"] = from_union([lambda x: to_class(PurpleCrumbIssuer, x), from_none], self.crumb_issuer)
        result["demand"] = from_union([lambda x: to_class(Demand, x), from_none], self.demand)
        result["descriptionColumn"] = from_union([lambda x: to_class(DescriptionColumn, x), from_none], self.description_column)
        result["directEntry"] = from_union([lambda x: to_class(JenkinsDirectEntry, x), from_none], self.direct_entry)
        result["disabledAdministrativeMonitors"] = from_union([from_str, from_none], self.disabled_administrative_monitors)
        result["disableRememberMe"] = from_union([from_bool, from_none], self.disable_remember_me)
        result["domain"] = from_union([lambda x: to_class(JenkinsDomain, x), from_none], self.domain)
        result["domainCredentials"] = from_union([lambda x: to_class(JenkinsDomainCredentials, x), from_none], self.domain_credentials)
        result["domainSpecification"] = from_union([lambda x: to_class(JenkinsDomainSpecification, x), from_none], self.domain_specification)
        result["entry"] = from_union([lambda x: to_class(Entry, x), from_none], self.entry)
        result["file"] = from_union([lambda x: to_class(JenkinsFile, x), from_none], self.file)
        result["gitBranchSpecifierColumn"] = from_union([lambda x: to_class(GitBranchSpecifierColumn, x), from_none], self.git_branch_specifier_column)
        result["hostnamePortSpecification"] = from_union([lambda x: to_class(JenkinsHostnamePortSpecification, x), from_none], self.hostname_port_specification)
        result["hostnameSpecification"] = from_union([lambda x: to_class(JenkinsHostnameSpecification, x), from_none], self.hostname_specification)
        result["inheritanceStrategy"] = from_union([lambda x: to_class(JenkinsInheritanceStrategy, x), from_none], self.inheritance_strategy)
        result["inheriting"] = from_union([lambda x: to_class(Inheriting, x), from_none], self.inheriting)
        result["inheritingGlobal"] = from_union([lambda x: to_class(InheritingGlobal, x), from_none], self.inheriting_global)
        result["itemColumn"] = from_union([lambda x: to_class(ItemColumn, x), from_none], self.item_column)
        result["jdk"] = from_union([lambda x: to_class(JenkinsJDK, x), from_none], self.jdk)
        result["jdkInstaller"] = from_union([lambda x: to_class(JenkinsJDKInstaller, x), from_none], self.jdk_installer)
        result["jDKs"] = from_union([lambda x: to_class(JDKs, x), from_none], self.j_d_ks)
        result["jenkins"] = from_union([lambda x: to_class(JenkinsClass, x), from_none], self.jenkins)
        result["jnlp"] = from_union([lambda x: to_class(Jnlp, x), from_none], self.jnlp)
        result["jobName"] = from_union([lambda x: to_class(JobName, x), from_none], self.job_name)
        result["keyStoreSource"] = from_union([lambda x: to_class(JenkinsKeyStoreSource, x), from_none], self.key_store_source)
        result["knownHostsFileKeyVerificationStrategy"] = from_union([lambda x: to_class(KnownHostsFileKeyVerificationStrategy, x), from_none], self.known_hosts_file_key_verification_strategy)
        result["labelAtom"] = from_union([lambda x: to_class(PurpleLabelAtom, x), from_none], self.label_atom)
        result["labelAtoms"] = from_union([lambda x: to_class(LabelAtoms, x), from_none], self.label_atoms)
        result["labelString"] = from_union([from_str, from_none], self.label_string)
        result["lastDuration"] = from_union([lambda x: to_class(LastDuration, x), from_none], self.last_duration)
        result["lastFailure"] = from_union([lambda x: to_class(LastFailure, x), from_none], self.last_failure)
        result["lastStable"] = from_union([lambda x: to_class(LastStable, x), from_none], self.last_stable)
        result["lastSuccess"] = from_union([lambda x: to_class(LastSuccess, x), from_none], self.last_success)
        result["legacy"] = from_union([lambda x: to_class(Legacy, x), from_none], self.legacy)
        result["list"] = from_union([lambda x: to_class(ListClass, x), from_none], self.list)
        result["listViewColumn"] = from_union([lambda x: to_class(ListViewColumn, x), from_none], self.list_view_column)
        result["local"] = from_union([lambda x: to_class(Local, x), from_none], self.local)
        result["log"] = from_union([lambda x: to_class(FluffyLog, x), from_none], self.log)
        result["loggedInUsersCanDoAnything"] = from_union([lambda x: to_class(LoggedInUsersCanDoAnything, x), from_none], self.logged_in_users_can_do_anything)
        result["logRecorder"] = from_union([lambda x: to_class(LogRecorder, x), from_none], self.log_recorder)
        result["mailer"] = from_union([lambda x: to_class(JenkinsMailer, x), from_none], self.mailer)
        result["manuallyProvidedKeyVerificationStrategy"] = from_union([lambda x: to_class(ManuallyProvidedKeyVerificationStrategy, x), from_none], self.manually_provided_key_verification_strategy)
        result["manuallyTrustedKeyVerificationStrategy"] = from_union([lambda x: to_class(ManuallyTrustedKeyVerificationStrategy, x), from_none], self.manually_trusted_key_verification_strategy)
        result["markupFormatter"] = from_union([lambda x: to_class(FluffyMarkupFormatter, x), from_none], self.markup_formatter)
        result["maven"] = from_union([lambda x: to_class(JenkinsMaven, x), from_none], self.maven)
        result["mode"] = from_union([lambda x: to_enum(Mode, x), from_none], self.mode)
        result["myView"] = from_union([lambda x: to_class(JenkinsMyView, x), from_none], self.my_view)
        result["myViewsTabBar"] = from_union([lambda x: to_class(FluffyMyViewsTabBar, x), from_none], self.my_views_tab_bar)
        result["node"] = from_union([lambda x: to_class(PurpleNode, x), from_none], self.node)
        result["nodeName"] = from_union([from_str, from_none], self.node_name)
        result["nodeProperty"] = from_union([lambda x: to_class(FluffyNodeProperty, x), from_none], self.node_property)
        result["nonInheriting"] = from_union([lambda x: to_class(NonInheriting, x), from_none], self.non_inheriting)
        result["nonVerifyingKeyVerificationStrategy"] = from_union([lambda x: to_class(NonVerifyingKeyVerificationStrategy, x), from_none], self.non_verifying_key_verification_strategy)
        result["noUsageStatistics"] = from_union([from_bool, from_none], self.no_usage_statistics)
        result["numExecutors"] = from_union([from_int, from_none], self.num_executors)
        result["pam"] = from_union([lambda x: to_class(Pam, x), from_none], self.pam)
        result["pathSpecification"] = from_union([lambda x: to_class(JenkinsPathSpecification, x), from_none], self.path_specification)
        result["pattern"] = from_union([lambda x: to_class(Pattern, x), from_none], self.pattern)
        result["permanent"] = from_union([lambda x: to_class(Permanent, x), from_none], self.permanent)
        result["plainText"] = from_union([lambda x: to_class(PlainText, x), from_none], self.plain_text)
        result["preferredProvider"] = from_union([lambda x: to_class(PreferredProvider, x), from_none], self.preferred_provider)
        result["privateKeySource"] = from_union([lambda x: to_class(JenkinsPrivateKeySource, x), from_none], self.private_key_source)
        result["projectNamingStrategy"] = from_union([lambda x: to_class(FluffyProjectNamingStrategy, x), from_none], self.project_naming_strategy)
        result["proxy"] = from_union([lambda x: to_class(FluffyProxy, x), from_none], self.proxy)
        result["quietPeriod"] = from_union([from_int, from_none], self.quiet_period)
        result["rawBuildsDir"] = from_union([from_str, from_none], self.raw_builds_dir)
        result["rawHtml"] = from_union([lambda x: to_class(RawHTML, x), from_none], self.raw_html)
        result["remotingSecurity"] = from_union([lambda x: to_class(FluffyRemotingSecurity, x), from_none], self.remoting_security)
        result["retentionStrategy"] = from_union([lambda x: to_class(JenkinsRetentionStrategy, x), from_none], self.retention_strategy)
        result["schedule"] = from_union([lambda x: to_class(Schedule, x), from_none], self.schedule)
        result["schemeSpecification"] = from_union([lambda x: to_class(JenkinsSchemeSpecification, x), from_none], self.scheme_specification)
        result["scmCheckoutRetryCount"] = from_union([from_int, from_none], self.scm_checkout_retry_count)
        result["securityRealm"] = from_union([lambda x: to_class(FluffySecurityRealm, x), from_none], self.security_realm)
        result["slaveAgentPort"] = from_union([from_int, from_none], self.slave_agent_port)
        result["ssh"] = from_union([lambda x: to_class(SSH, x), from_none], self.ssh)
        result["sshHostKeyVerificationStrategy"] = from_union([lambda x: to_class(JenkinsSSHHostKeyVerificationStrategy, x), from_none], self.ssh_host_key_verification_strategy)
        result["sshPublicKey"] = from_union([lambda x: to_class(SSHPublicKey, x), from_none], self.ssh_public_key)
        result["standard"] = from_union([lambda x: to_class(JenkinsStandard, x), from_none], self.standard)
        result["status"] = from_union([lambda x: to_class(Status, x), from_none], self.status)
        result["statusFilter"] = from_union([lambda x: to_class(StatusFilter, x), from_none], self.status_filter)
        result["string"] = from_union([lambda x: to_class(JenkinsString, x), from_none], self.string)
        result["systemMessage"] = from_union([from_str, from_none], self.system_message)
        result["target"] = from_union([lambda x: to_class(Target, x), from_none], self.target)
        result["timezone"] = from_union([lambda x: to_class(Timezone, x), from_none], self.timezone)
        result["toolInstaller"] = from_union([lambda x: to_class(JenkinsToolInstaller, x), from_none], self.tool_installer)
        result["toolLocation"] = from_union([lambda x: to_class(ToolLocation, x), from_none], self.tool_location)
        result["toolProperty"] = from_union([lambda x: to_class(JenkinsToolProperty, x), from_none], self.tool_property)
        result["unsecured"] = from_union([lambda x: to_class(Unsecured, x), from_none], self.unsecured)
        result["updateCenter"] = from_union([lambda x: to_class(FluffyUpdateCenter, x), from_none], self.update_center)
        result["updateSite"] = from_union([lambda x: to_class(UpdateSite, x), from_none], self.update_site)
        result["uploaded"] = from_union([lambda x: to_class(JenkinsUploaded, x), from_none], self.uploaded)
        result["usernamePassword"] = from_union([lambda x: to_class(JenkinsUsernamePassword, x), from_none], self.username_password)
        result["userProperty"] = from_union([lambda x: to_class(UserProperty, x), from_none], self.user_property)
        result["userWithPassword"] = from_union([lambda x: to_class(UserWithPassword, x), from_none], self.user_with_password)
        result["view"] = from_union([lambda x: to_class(PurpleView, x), from_none], self.view)
        result["viewJobFilter"] = from_union([lambda x: to_class(ViewJobFilter, x), from_none], self.view_job_filter)
        result["viewsTabBar"] = from_union([lambda x: to_class(FluffyViewsTabBar, x), from_none], self.views_tab_bar)
        result["weather"] = from_union([lambda x: to_class(Weather, x), from_none], self.weather)
        result["zip"] = from_union([lambda x: to_class(JenkinsZip, x), from_none], self.zip)
        return result

@dataclass
class ScriptSource:
    file: Any
    script: Any
    url: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ScriptSource':
        assert isinstance(obj, dict)
        file = obj.get("file")
        script = obj.get("script")
        url = obj.get("url")
        return ScriptSource(file, script, url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["file"] = self.file
        result["script"] = self.script
        result["url"] = self.url
        return result

@dataclass
class Jobs:
    script_source: Optional[List[ScriptSource]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Jobs':
        assert isinstance(obj, dict)
        return Jobs()

    def to_dict(self) -> dict:
        result: dict = {}
        return result

@dataclass
class ConfigurationBaseForTheJobsClassifier:
    empty: Optional[Jobs] = None
    script_source: Optional[ScriptSource] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ConfigurationBaseForTheJobsClassifier':
        assert isinstance(obj, dict)
        empty = from_union([Jobs.from_dict, from_none], obj.get(""))
        script_source = from_union([ScriptSource.from_dict, from_none], obj.get("scriptSource"))
        return ConfigurationBaseForTheJobsClassifier(empty, script_source)

    def to_dict(self) -> dict:
        result: dict = {}
        result[""] = from_union([lambda x: to_class(Jobs, x), from_none], self.empty)
        result["scriptSource"] = from_union([lambda x: to_class(ScriptSource, x), from_none], self.script_source)
        return result


@dataclass
class SecurityAPIToken:
    """This option allows users to generate a legacy API token if they do not already have
    one.
    Because legacy tokens are deprecated, we recommend disabling it and having users instead
    generate
    new API tokens from the user configuration page.
    """
    creation_of_legacy_token_enabled: Optional[bool] = None
    """This option causes a legacy API token to be generated automatically for newly created
    users.
    Because legacy tokens are deprecated, we recommend disabling it and having users instead
    generate
    new API tokens from the user configuration page as needed.
    """
    token_generation_on_creation_enabled: Optional[bool] = None
    """If this option is enabled, then the date of the most recent use of each API token and the
    total number of times
    it has been used are stored in Jenkins.
    This allows users to see if they have unused or outdated API tokens which should be
    revoked.
    
    
    This data is stored in your Jenkins instance and will not be used for any other purpose.
    """
    usage_statistics_enabled: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SecurityAPIToken':
        assert isinstance(obj, dict)
        creation_of_legacy_token_enabled = from_union([from_bool, from_none], obj.get("creationOfLegacyTokenEnabled"))
        token_generation_on_creation_enabled = from_union([from_bool, from_none], obj.get("tokenGenerationOnCreationEnabled"))
        usage_statistics_enabled = from_union([from_bool, from_none], obj.get("usageStatisticsEnabled"))
        return SecurityAPIToken(creation_of_legacy_token_enabled, token_generation_on_creation_enabled, usage_statistics_enabled)

    def to_dict(self) -> dict:
        result: dict = {}
        result["creationOfLegacyTokenEnabled"] = from_union([from_bool, from_none], self.creation_of_legacy_token_enabled)
        result["tokenGenerationOnCreationEnabled"] = from_union([from_bool, from_none], self.token_generation_on_creation_enabled)
        result["usageStatisticsEnabled"] = from_union([from_bool, from_none], self.usage_statistics_enabled)
        return result


@dataclass
class Crumb:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Crumb':
        assert isinstance(obj, dict)
        return Crumb()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class GlobalJobDSLSecurityConfiguration:
    use_script_security: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GlobalJobDSLSecurityConfiguration':
        assert isinstance(obj, dict)
        use_script_security = from_union([from_bool, from_none], obj.get("useScriptSecurity"))
        return GlobalJobDSLSecurityConfiguration(use_script_security)

    def to_dict(self) -> dict:
        result: dict = {}
        result["useScriptSecurity"] = from_union([from_bool, from_none], self.use_script_security)
        return result


@dataclass
class SSHD:
    """Jenkins can act as an SSH server to run a subset of Jenkins CLI commands.
    Plugins may also use this service to expose additional commands. Specify this TCP/IP port
    number.
    """
    port: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SSHD':
        assert isinstance(obj, dict)
        port = from_union([from_int, from_none], obj.get("port"))
        return SSHD(port)

    def to_dict(self) -> dict:
        result: dict = {}
        result["port"] = from_union([from_int, from_none], self.port)
        return result


@dataclass
class ScriptApproval:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ScriptApproval':
        assert isinstance(obj, dict)
        return ScriptApproval()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UpdateSiteWarningsConfiguration:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UpdateSiteWarningsConfiguration':
        assert isinstance(obj, dict)
        return UpdateSiteWarningsConfiguration()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ConfigurationBaseForTheSecurityClassifier:
    queue_item_authenticator: Any
    api_token: Optional[SecurityAPIToken] = None
    crumb: Optional[Crumb] = None
    global_job_dsl_security_configuration: Optional[GlobalJobDSLSecurityConfiguration] = None
    script_approval: Optional[ScriptApproval] = None
    s_shd: Optional[SSHD] = None
    update_site_warnings_configuration: Optional[UpdateSiteWarningsConfiguration] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ConfigurationBaseForTheSecurityClassifier':
        assert isinstance(obj, dict)
        queue_item_authenticator = obj.get("queueItemAuthenticator")
        api_token = from_union([SecurityAPIToken.from_dict, from_none], obj.get("apiToken"))
        crumb = from_union([Crumb.from_dict, from_none], obj.get("crumb"))
        global_job_dsl_security_configuration = from_union([GlobalJobDSLSecurityConfiguration.from_dict, from_none], obj.get("globalJobDslSecurityConfiguration"))
        script_approval = from_union([ScriptApproval.from_dict, from_none], obj.get("scriptApproval"))
        s_shd = from_union([SSHD.from_dict, from_none], obj.get("sSHD"))
        update_site_warnings_configuration = from_union([UpdateSiteWarningsConfiguration.from_dict, from_none], obj.get("updateSiteWarningsConfiguration"))
        return ConfigurationBaseForTheSecurityClassifier(queue_item_authenticator, api_token, crumb, global_job_dsl_security_configuration, script_approval, s_shd, update_site_warnings_configuration)

    def to_dict(self) -> dict:
        result: dict = {}
        result["queueItemAuthenticator"] = self.queue_item_authenticator
        result["apiToken"] = from_union([lambda x: to_class(SecurityAPIToken, x), from_none], self.api_token)
        result["crumb"] = from_union([lambda x: to_class(Crumb, x), from_none], self.crumb)
        result["globalJobDslSecurityConfiguration"] = from_union([lambda x: to_class(GlobalJobDSLSecurityConfiguration, x), from_none], self.global_job_dsl_security_configuration)
        result["scriptApproval"] = from_union([lambda x: to_class(ScriptApproval, x), from_none], self.script_approval)
        result["sSHD"] = from_union([lambda x: to_class(SSHD, x), from_none], self.s_shd)
        result["updateSiteWarningsConfiguration"] = from_union([lambda x: to_class(UpdateSiteWarningsConfiguration, x), from_none], self.update_site_warnings_configuration)
        return result


@dataclass
class ToolBatchFile:
    command: Optional[str] = None
    label: Optional[str] = None
    tool_home: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ToolBatchFile':
        assert isinstance(obj, dict)
        command = from_union([from_str, from_none], obj.get("command"))
        label = from_union([from_str, from_none], obj.get("label"))
        tool_home = from_union([from_str, from_none], obj.get("toolHome"))
        return ToolBatchFile(command, label, tool_home)

    def to_dict(self) -> dict:
        result: dict = {}
        result["command"] = from_union([from_str, from_none], self.command)
        result["label"] = from_union([from_str, from_none], self.label)
        result["toolHome"] = from_union([from_str, from_none], self.tool_home)
        return result


@dataclass
class ToolCommand:
    command: Optional[str] = None
    label: Optional[str] = None
    tool_home: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ToolCommand':
        assert isinstance(obj, dict)
        command = from_union([from_str, from_none], obj.get("command"))
        label = from_union([from_str, from_none], obj.get("label"))
        tool_home = from_union([from_str, from_none], obj.get("toolHome"))
        return ToolCommand(command, label, tool_home)

    def to_dict(self) -> dict:
        result: dict = {}
        result["command"] = from_union([from_str, from_none], self.command)
        result["label"] = from_union([from_str, from_none], self.label)
        result["toolHome"] = from_union([from_str, from_none], self.tool_home)
        return result


@dataclass
class FilePath:
    """Path to settings.xml file, relative to project workspace or absolute (variables are
    supported).
    """
    path: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'FilePath':
        assert isinstance(obj, dict)
        path = from_union([from_str, from_none], obj.get("path"))
        return FilePath(path)

    def to_dict(self) -> dict:
        result: dict = {}
        result["path"] = from_union([from_str, from_none], self.path)
        return result


@dataclass
class GitProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GitProperty':
        assert isinstance(obj, dict)
        return GitProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ToolGit:
    """Set path to git executable. This can be just "git" or complete path."""
    home: Optional[str] = None
    name: Optional[str] = None
    properties: Optional[List[GitProperty]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ToolGit':
        assert isinstance(obj, dict)
        home = from_union([from_str, from_none], obj.get("home"))
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([lambda x: from_list(GitProperty.from_dict, x), from_none], obj.get("properties"))
        return ToolGit(home, name, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["home"] = from_union([from_str, from_none], self.home)
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: from_list(lambda x: to_class(GitProperty, x), x), from_none], self.properties)
        return result


@dataclass
class ToolGlobalSettingsProvider:
    standard: Any
    file_path: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ToolGlobalSettingsProvider':
        assert isinstance(obj, dict)
        standard = obj.get("standard")
        file_path = obj.get("filePath")
        return ToolGlobalSettingsProvider(standard, file_path)

    def to_dict(self) -> dict:
        result: dict = {}
        result["standard"] = self.standard
        result["filePath"] = self.file_path
        return result


@dataclass
class FluffyProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FluffyProperty':
        assert isinstance(obj, dict)
        return FluffyProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ToolJDK:
    home: Optional[str] = None
    name: Optional[str] = None
    properties: Optional[List[FluffyProperty]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ToolJDK':
        assert isinstance(obj, dict)
        home = from_union([from_str, from_none], obj.get("home"))
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([lambda x: from_list(FluffyProperty.from_dict, x), from_none], obj.get("properties"))
        return ToolJDK(home, name, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["home"] = from_union([from_str, from_none], self.home)
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: from_list(lambda x: to_class(FluffyProperty, x), x), from_none], self.properties)
        return result


@dataclass
class ToolJDKInstaller:
    accept_license: Optional[bool] = None
    id: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ToolJDKInstaller':
        assert isinstance(obj, dict)
        accept_license = from_union([from_bool, from_none], obj.get("acceptLicense"))
        id = from_union([from_str, from_none], obj.get("id"))
        return ToolJDKInstaller(accept_license, id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["acceptLicense"] = from_union([from_bool, from_none], self.accept_license)
        result["id"] = from_union([from_str, from_none], self.id)
        return result


@dataclass
class Jgit:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Jgit':
        assert isinstance(obj, dict)
        return Jgit()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Jgitapache:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Jgitapache':
        assert isinstance(obj, dict)
        return Jgitapache()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class MavenProperty:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'MavenProperty':
        assert isinstance(obj, dict)
        return MavenProperty()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ToolMaven:
    home: Optional[str] = None
    name: Optional[str] = None
    properties: Optional[List[MavenProperty]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ToolMaven':
        assert isinstance(obj, dict)
        home = from_union([from_str, from_none], obj.get("home"))
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([lambda x: from_list(MavenProperty.from_dict, x), from_none], obj.get("properties"))
        return ToolMaven(home, name, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["home"] = from_union([from_str, from_none], self.home)
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: from_list(lambda x: to_class(MavenProperty, x), x), from_none], self.properties)
        return result


@dataclass
class MavenGlobalConfigGlobalSettingsProvider:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'MavenGlobalConfigGlobalSettingsProvider':
        assert isinstance(obj, dict)
        return MavenGlobalConfigGlobalSettingsProvider()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class InstallationProperties:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'InstallationProperties':
        assert isinstance(obj, dict)
        return InstallationProperties()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Installation:
    home: Optional[str] = None
    name: Optional[str] = None
    properties: Optional[InstallationProperties] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Installation':
        assert isinstance(obj, dict)
        home = from_union([from_str, from_none], obj.get("home"))
        name = from_union([from_str, from_none], obj.get("name"))
        properties = from_union([InstallationProperties.from_dict, from_none], obj.get("properties"))
        return Installation(home, name, properties)

    def to_dict(self) -> dict:
        result: dict = {}
        result["home"] = from_union([from_str, from_none], self.home)
        result["name"] = from_union([from_str, from_none], self.name)
        result["properties"] = from_union([lambda x: to_class(InstallationProperties, x), from_none], self.properties)
        return result


@dataclass
class MavenGlobalConfigSettingsProvider:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'MavenGlobalConfigSettingsProvider':
        assert isinstance(obj, dict)
        return MavenGlobalConfigSettingsProvider()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class MavenGlobalConfig:
    global_settings_provider: Optional[MavenGlobalConfigGlobalSettingsProvider] = None
    installations: Optional[List[Installation]] = None
    settings_provider: Optional[MavenGlobalConfigSettingsProvider] = None

    @staticmethod
    def from_dict(obj: Any) -> 'MavenGlobalConfig':
        assert isinstance(obj, dict)
        global_settings_provider = from_union([MavenGlobalConfigGlobalSettingsProvider.from_dict, from_none], obj.get("globalSettingsProvider"))
        installations = from_union([lambda x: from_list(Installation.from_dict, x), from_none], obj.get("installations"))
        settings_provider = from_union([MavenGlobalConfigSettingsProvider.from_dict, from_none], obj.get("settingsProvider"))
        return MavenGlobalConfig(global_settings_provider, installations, settings_provider)

    def to_dict(self) -> dict:
        result: dict = {}
        result["globalSettingsProvider"] = from_union([lambda x: to_class(MavenGlobalConfigGlobalSettingsProvider, x), from_none], self.global_settings_provider)
        result["installations"] = from_union([lambda x: from_list(lambda x: to_class(Installation, x), x), from_none], self.installations)
        result["settingsProvider"] = from_union([lambda x: to_class(MavenGlobalConfigSettingsProvider, x), from_none], self.settings_provider)
        return result


@dataclass
class ToolSettingsProvider:
    standard: Any
    file_path: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ToolSettingsProvider':
        assert isinstance(obj, dict)
        standard = obj.get("standard")
        file_path = obj.get("filePath")
        return ToolSettingsProvider(standard, file_path)

    def to_dict(self) -> dict:
        result: dict = {}
        result["standard"] = self.standard
        result["filePath"] = self.file_path
        return result


@dataclass
class ToolStandard:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ToolStandard':
        assert isinstance(obj, dict)
        return ToolStandard()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ToolInstallation:
    jdk: Any
    git: Any
    maven: Any
    jgit: Any
    jgitapache: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ToolInstallation':
        assert isinstance(obj, dict)
        jdk = obj.get("jdk")
        git = obj.get("git")
        maven = obj.get("maven")
        jgit = obj.get("jgit")
        jgitapache = obj.get("jgitapache")
        return ToolInstallation(jdk, git, maven, jgit, jgitapache)

    def to_dict(self) -> dict:
        result: dict = {}
        result["jdk"] = self.jdk
        result["git"] = self.git
        result["maven"] = self.maven
        result["jgit"] = self.jgit
        result["jgitapache"] = self.jgitapache
        return result


@dataclass
class ToolToolInstaller:
    zip: Any
    batch_file: Any
    jdk_installer: Any
    maven: Any
    command: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ToolToolInstaller':
        assert isinstance(obj, dict)
        zip = obj.get("zip")
        batch_file = obj.get("batchFile")
        jdk_installer = obj.get("jdkInstaller")
        maven = obj.get("maven")
        command = obj.get("command")
        return ToolToolInstaller(zip, batch_file, jdk_installer, maven, command)

    def to_dict(self) -> dict:
        result: dict = {}
        result["zip"] = self.zip
        result["batchFile"] = self.batch_file
        result["jdkInstaller"] = self.jdk_installer
        result["maven"] = self.maven
        result["command"] = self.command
        return result


@dataclass
class ToolToolProperty:
    install_source: Any

    @staticmethod
    def from_dict(obj: Any) -> 'ToolToolProperty':
        assert isinstance(obj, dict)
        install_source = obj.get("installSource")
        return ToolToolProperty(install_source)

    def to_dict(self) -> dict:
        result: dict = {}
        result["installSource"] = self.install_source
        return result


@dataclass
class ToolZip:
    label: Optional[str] = None
    """Optional subdirectory of the downloaded and unpacked archive to use as the tool's home
    directory.
    """
    subdir: Optional[str] = None
    """URL from which to download the tool in binary form.
    Should be either a ZIP or a GZip-compressed TAR file.
    The timestamp on the server will be compared to the local version (if any)
    so you can publish updates easily.
    The URL must be accessible from the Jenkins controller but need not be accessible from
    agents.
    """
    url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ToolZip':
        assert isinstance(obj, dict)
        label = from_union([from_str, from_none], obj.get("label"))
        subdir = from_union([from_str, from_none], obj.get("subdir"))
        url = from_union([from_str, from_none], obj.get("url"))
        return ToolZip(label, subdir, url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["label"] = from_union([from_str, from_none], self.label)
        result["subdir"] = from_union([from_str, from_none], self.subdir)
        result["url"] = from_union([from_str, from_none], self.url)
        return result


@dataclass
class ConfigurationBaseForTheToolClassifier:
    batch_file: Optional[ToolBatchFile] = None
    command: Optional[ToolCommand] = None
    file_path: Optional[FilePath] = None
    git: Optional[ToolGit] = None
    global_settings_provider: Optional[ToolGlobalSettingsProvider] = None
    jdk: Optional[ToolJDK] = None
    jdk_installer: Optional[ToolJDKInstaller] = None
    jgit: Optional[Jgit] = None
    jgitapache: Optional[Jgitapache] = None
    maven: Optional[ToolMaven] = None
    maven_global_config: Optional[MavenGlobalConfig] = None
    settings_provider: Optional[ToolSettingsProvider] = None
    standard: Optional[ToolStandard] = None
    tool_installation: Optional[ToolInstallation] = None
    tool_installer: Optional[ToolToolInstaller] = None
    tool_property: Optional[ToolToolProperty] = None
    zip: Optional[ToolZip] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ConfigurationBaseForTheToolClassifier':
        assert isinstance(obj, dict)
        batch_file = from_union([ToolBatchFile.from_dict, from_none], obj.get("batchFile"))
        command = from_union([ToolCommand.from_dict, from_none], obj.get("command"))
        file_path = from_union([FilePath.from_dict, from_none], obj.get("filePath"))
        git = from_union([ToolGit.from_dict, from_none], obj.get("git"))
        global_settings_provider = from_union([ToolGlobalSettingsProvider.from_dict, from_none], obj.get("globalSettingsProvider"))
        jdk = from_union([ToolJDK.from_dict, from_none], obj.get("jdk"))
        jdk_installer = from_union([ToolJDKInstaller.from_dict, from_none], obj.get("jdkInstaller"))
        jgit = from_union([Jgit.from_dict, from_none], obj.get("jgit"))
        jgitapache = from_union([Jgitapache.from_dict, from_none], obj.get("jgitapache"))
        maven = from_union([ToolMaven.from_dict, from_none], obj.get("maven"))
        maven_global_config = from_union([MavenGlobalConfig.from_dict, from_none], obj.get("mavenGlobalConfig"))
        settings_provider = from_union([ToolSettingsProvider.from_dict, from_none], obj.get("settingsProvider"))
        standard = from_union([ToolStandard.from_dict, from_none], obj.get("standard"))
        tool_installation = from_union([ToolInstallation.from_dict, from_none], obj.get("toolInstallation"))
        tool_installer = from_union([ToolToolInstaller.from_dict, from_none], obj.get("toolInstaller"))
        tool_property = from_union([ToolToolProperty.from_dict, from_none], obj.get("toolProperty"))
        zip = from_union([ToolZip.from_dict, from_none], obj.get("zip"))
        return ConfigurationBaseForTheToolClassifier(batch_file, command, file_path, git, global_settings_provider, jdk, jdk_installer, jgit, jgitapache, maven, maven_global_config, settings_provider, standard, tool_installation, tool_installer, tool_property, zip)

    def to_dict(self) -> dict:
        result: dict = {}
        result["batchFile"] = from_union([lambda x: to_class(ToolBatchFile, x), from_none], self.batch_file)
        result["command"] = from_union([lambda x: to_class(ToolCommand, x), from_none], self.command)
        result["filePath"] = from_union([lambda x: to_class(FilePath, x), from_none], self.file_path)
        result["git"] = from_union([lambda x: to_class(ToolGit, x), from_none], self.git)
        result["globalSettingsProvider"] = from_union([lambda x: to_class(ToolGlobalSettingsProvider, x), from_none], self.global_settings_provider)
        result["jdk"] = from_union([lambda x: to_class(ToolJDK, x), from_none], self.jdk)
        result["jdkInstaller"] = from_union([lambda x: to_class(ToolJDKInstaller, x), from_none], self.jdk_installer)
        result["jgit"] = from_union([lambda x: to_class(Jgit, x), from_none], self.jgit)
        result["jgitapache"] = from_union([lambda x: to_class(Jgitapache, x), from_none], self.jgitapache)
        result["maven"] = from_union([lambda x: to_class(ToolMaven, x), from_none], self.maven)
        result["mavenGlobalConfig"] = from_union([lambda x: to_class(MavenGlobalConfig, x), from_none], self.maven_global_config)
        result["settingsProvider"] = from_union([lambda x: to_class(ToolSettingsProvider, x), from_none], self.settings_provider)
        result["standard"] = from_union([lambda x: to_class(ToolStandard, x), from_none], self.standard)
        result["toolInstallation"] = from_union([lambda x: to_class(ToolInstallation, x), from_none], self.tool_installation)
        result["toolInstaller"] = from_union([lambda x: to_class(ToolToolInstaller, x), from_none], self.tool_installer)
        result["toolProperty"] = from_union([lambda x: to_class(ToolToolProperty, x), from_none], self.tool_property)
        result["zip"] = from_union([lambda x: to_class(ToolZip, x), from_none], self.zip)
        return result


@dataclass
class AdministrativeMonitorsConfiguration:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'AdministrativeMonitorsConfiguration':
        assert isinstance(obj, dict)
        return AdministrativeMonitorsConfiguration()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Ancestry:
    ancestor_commit_sha1: Optional[str] = None
    maximum_age_in_days: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Ancestry':
        assert isinstance(obj, dict)
        ancestor_commit_sha1 = from_union([from_str, from_none], obj.get("ancestorCommitSha1"))
        maximum_age_in_days = from_union([from_int, from_none], obj.get("maximumAgeInDays"))
        return Ancestry(ancestor_commit_sha1, maximum_age_in_days)

    def to_dict(self) -> dict:
        result: dict = {}
        result["ancestorCommitSha1"] = from_union([from_str, from_none], self.ancestor_commit_sha1)
        result["maximumAgeInDays"] = from_union([from_int, from_none], self.maximum_age_in_days)
        return result


@dataclass
class ArtifactManager:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ArtifactManager':
        assert isinstance(obj, dict)
        return ArtifactManager()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class AssemblaWeb:
    """Specify the root URL serving this repository (such as
    https://www.assembla.com/code/PROJECT/git/).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'AssemblaWeb':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return AssemblaWeb(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class AuthorInChangelog:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'AuthorInChangelog':
        assert isinstance(obj, dict)
        return AuthorInChangelog()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class BitbucketServer:
    """Specify the Bitbucket Server root URL for this repository (such as
    https://bitbucket:7990/OWNER/REPO/).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'BitbucketServer':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return BitbucketServer(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class BitbucketWeb:
    """Specify the root URL serving this repository (such as https://bitbucket.org/OWNER/REPO/)."""
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'BitbucketWeb':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return BitbucketWeb(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class UnclassifiedBuildChooser:
    inverse: Any
    default: Any
    ancestry: Any

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedBuildChooser':
        assert isinstance(obj, dict)
        inverse = obj.get("inverse")
        default = obj.get("default")
        ancestry = obj.get("ancestry")
        return UnclassifiedBuildChooser(inverse, default, ancestry)

    def to_dict(self) -> dict:
        result: dict = {}
        result["inverse"] = self.inverse
        result["default"] = self.default
        result["ancestry"] = self.ancestry
        return result


@dataclass
class BuildChooserSettingBuildChooser:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'BuildChooserSettingBuildChooser':
        assert isinstance(obj, dict)
        return BuildChooserSettingBuildChooser()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class BuildChooserSetting:
    build_chooser: Optional[BuildChooserSettingBuildChooser] = None

    @staticmethod
    def from_dict(obj: Any) -> 'BuildChooserSetting':
        assert isinstance(obj, dict)
        build_chooser = from_union([BuildChooserSettingBuildChooser.from_dict, from_none], obj.get("buildChooser"))
        return BuildChooserSetting(build_chooser)

    def to_dict(self) -> dict:
        result: dict = {}
        result["buildChooser"] = from_union([lambda x: to_class(BuildChooserSettingBuildChooser, x), from_none], self.build_chooser)
        return result


@dataclass
class BuildDiscarder:
    log_rotator: Any

    @staticmethod
    def from_dict(obj: Any) -> 'BuildDiscarder':
        assert isinstance(obj, dict)
        log_rotator = obj.get("logRotator")
        return BuildDiscarder(log_rotator)

    def to_dict(self) -> dict:
        result: dict = {}
        result["logRotator"] = self.log_rotator
        return result


@dataclass
class BuildDiscarders:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'BuildDiscarders':
        assert isinstance(obj, dict)
        return BuildDiscarders()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class BuildSingleRevisionOnly:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'BuildSingleRevisionOnly':
        assert isinstance(obj, dict)
        return BuildSingleRevisionOnly()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class BuildStepOperation:
    enabled: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'BuildStepOperation':
        assert isinstance(obj, dict)
        enabled = from_union([from_bool, from_none], obj.get("enabled"))
        return BuildStepOperation(enabled)

    def to_dict(self) -> dict:
        result: dict = {}
        result["enabled"] = from_union([from_bool, from_none], self.enabled)
        return result


@dataclass
class BuiltInNode:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'BuiltInNode':
        assert isinstance(obj, dict)
        return BuiltInNode()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class CGit:
    """Specify the root URL serving this repository (such as
    http://cgit.example.com:port/group/REPO/).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CGit':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return CGit(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class CasCGlobalConfig:
    configuration_path: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CasCGlobalConfig':
        assert isinstance(obj, dict)
        configuration_path = from_union([from_str, from_none], obj.get("configurationPath"))
        return CasCGlobalConfig(configuration_path)

    def to_dict(self) -> dict:
        result: dict = {}
        result["configurationPath"] = from_union([from_str, from_none], self.configuration_path)
        return result


@dataclass
class ChangelogToBranchOptions:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ChangelogToBranchOptions':
        assert isinstance(obj, dict)
        return ChangelogToBranchOptions()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ChangelogToBranch:
    options: Optional[ChangelogToBranchOptions] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ChangelogToBranch':
        assert isinstance(obj, dict)
        options = from_union([ChangelogToBranchOptions.from_dict, from_none], obj.get("options"))
        return ChangelogToBranch(options)

    def to_dict(self) -> dict:
        result: dict = {}
        result["options"] = from_union([lambda x: to_class(ChangelogToBranchOptions, x), from_none], self.options)
        return result


@dataclass
class CheckoutOption:
    """Specify a timeout (in minutes) for checkout.
    This option overrides the default timeout of 10 minutes.
    You can change the global git timeout via the property
    org.jenkinsci.plugins.gitclient.Git.timeOut (see JENKINS-11286).
    Note that property should be set on both controller and agent to have effect (see
    JENKINS-22547).
    """
    timeout: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CheckoutOption':
        assert isinstance(obj, dict)
        timeout = from_union([from_int, from_none], obj.get("timeout"))
        return CheckoutOption(timeout)

    def to_dict(self) -> dict:
        result: dict = {}
        result["timeout"] = from_union([from_int, from_none], self.timeout)
        return result


@dataclass
class CleanBeforeCheckout:
    """Deletes untracked submodules and any other subdirectories which contain .git directories."""
    delete_untracked_nested_repositories: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CleanBeforeCheckout':
        assert isinstance(obj, dict)
        delete_untracked_nested_repositories = from_union([from_bool, from_none], obj.get("deleteUntrackedNestedRepositories"))
        return CleanBeforeCheckout(delete_untracked_nested_repositories)

    def to_dict(self) -> dict:
        result: dict = {}
        result["deleteUntrackedNestedRepositories"] = from_union([from_bool, from_none], self.delete_untracked_nested_repositories)
        return result


@dataclass
class CleanCheckout:
    """Deletes untracked submodules and any other subdirectories which contain .git directories."""
    delete_untracked_nested_repositories: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CleanCheckout':
        assert isinstance(obj, dict)
        delete_untracked_nested_repositories = from_union([from_bool, from_none], obj.get("deleteUntrackedNestedRepositories"))
        return CleanCheckout(delete_untracked_nested_repositories)

    def to_dict(self) -> dict:
        result: dict = {}
        result["deleteUntrackedNestedRepositories"] = from_union([from_bool, from_none], self.delete_untracked_nested_repositories)
        return result


@dataclass
class CloneOption:
    """Set shallow clone depth, so that git will only download recent history of the project,
    saving time and disk space when you just want to access the latest commits of a
    repository.
    """
    depth: Optional[int] = None
    """Perform initial clone using the refspec defined for the repository.
    This can save time, data transfer and disk space when you only need
    to access the references specified by the refspec.
    """
    honor_refspec: Optional[bool] = None
    """Deselect this to perform a clone without tags, saving time and disk space when you just
    want to access
    what is specified by the refspec.
    """
    no_tags: Optional[bool] = None
    """Specify a folder containing a repository that will be used by Git as a reference during
    clone operations.
    This option will be ignored if the folder is not available on the controller or agent
    where the clone is being executed.
    """
    reference: Optional[str] = None
    """Perform shallow clone, so that git will not download the history of the project,
    saving time and disk space when you just want to access the latest version of a
    repository.
    """
    shallow: Optional[bool] = None
    """Specify a timeout (in minutes) for clone and fetch operations.
    This option overrides the default timeout of 10 minutes.
    You can change the global git timeout via the property
    org.jenkinsci.plugins.gitclient.Git.timeOut (see JENKINS-11286).
    Note that property should be set on both controller and agent to have effect (see
    JENKINS-22547).
    """
    timeout: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'CloneOption':
        assert isinstance(obj, dict)
        depth = from_union([from_int, from_none], obj.get("depth"))
        honor_refspec = from_union([from_bool, from_none], obj.get("honorRefspec"))
        no_tags = from_union([from_bool, from_none], obj.get("noTags"))
        reference = from_union([from_str, from_none], obj.get("reference"))
        shallow = from_union([from_bool, from_none], obj.get("shallow"))
        timeout = from_union([from_int, from_none], obj.get("timeout"))
        return CloneOption(depth, honor_refspec, no_tags, reference, shallow, timeout)

    def to_dict(self) -> dict:
        result: dict = {}
        result["depth"] = from_union([from_int, from_none], self.depth)
        result["honorRefspec"] = from_union([from_bool, from_none], self.honor_refspec)
        result["noTags"] = from_union([from_bool, from_none], self.no_tags)
        result["reference"] = from_union([from_str, from_none], self.reference)
        result["shallow"] = from_union([from_bool, from_none], self.shallow)
        result["timeout"] = from_union([from_int, from_none], self.timeout)
        return result


@dataclass
class Default:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Default':
        assert isinstance(obj, dict)
        return Default()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class DefaultFolderConfiguration:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'DefaultFolderConfiguration':
        assert isinstance(obj, dict)
        return DefaultFolderConfiguration()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class DefaultView:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'DefaultView':
        assert isinstance(obj, dict)
        return DefaultView()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class DisableRemotePoll:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'DisableRemotePoll':
        assert isinstance(obj, dict)
        return DisableRemotePoll()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Password:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Password':
        assert isinstance(obj, dict)
        return Password()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Unclassified:
    password: Optional[Password] = None
    username: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Unclassified':
        assert isinstance(obj, dict)
        password = from_union([Password.from_dict, from_none], obj.get("password"))
        username = from_union([from_str, from_none], obj.get("username"))
        return Unclassified(password, username)

    def to_dict(self) -> dict:
        result: dict = {}
        result["password"] = from_union([lambda x: to_class(Password, x), from_none], self.password)
        result["username"] = from_union([from_str, from_none], self.username)
        return result


@dataclass
class EnvVarsFilter:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'EnvVarsFilter':
        assert isinstance(obj, dict)
        return EnvVarsFilter()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UnclassifiedFile:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedFile':
        assert isinstance(obj, dict)
        return UnclassifiedFile()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FingerprintStorage:
    file: Any

    @staticmethod
    def from_dict(obj: Any) -> 'FingerprintStorage':
        assert isinstance(obj, dict)
        file = obj.get("file")
        return FingerprintStorage(file)

    def to_dict(self) -> dict:
        result: dict = {}
        result["file"] = self.file
        return result


@dataclass
class Storage:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Storage':
        assert isinstance(obj, dict)
        return Storage()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Fingerprints:
    fingerprint_cleanup_disabled: Optional[bool] = None
    storage: Optional[Storage] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Fingerprints':
        assert isinstance(obj, dict)
        fingerprint_cleanup_disabled = from_union([from_bool, from_none], obj.get("fingerprintCleanupDisabled"))
        storage = from_union([Storage.from_dict, from_none], obj.get("storage"))
        return Fingerprints(fingerprint_cleanup_disabled, storage)

    def to_dict(self) -> dict:
        result: dict = {}
        result["fingerprintCleanupDisabled"] = from_union([from_bool, from_none], self.fingerprint_cleanup_disabled)
        result["storage"] = from_union([lambda x: to_class(Storage, x), from_none], self.storage)
        return result


@dataclass
class FisheyeGit:
    """Specify the URL of this repository in FishEye (such as
    http://fisheye6.cenqua.com/browse/ant/).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'FisheyeGit':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return FisheyeGit(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class FolderHealthMetric:
    primary_branch_health_metric: Any
    worst_child_health_metric: Any

    @staticmethod
    def from_dict(obj: Any) -> 'FolderHealthMetric':
        assert isinstance(obj, dict)
        primary_branch_health_metric = obj.get("primaryBranchHealthMetric")
        worst_child_health_metric = obj.get("worstChildHealthMetric")
        return FolderHealthMetric(primary_branch_health_metric, worst_child_health_metric)

    def to_dict(self) -> dict:
        result: dict = {}
        result["primaryBranchHealthMetric"] = self.primary_branch_health_metric
        result["worstChildHealthMetric"] = self.worst_child_health_metric
        return result


@dataclass
class FromSCMSCM:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'FromSCMSCM':
        assert isinstance(obj, dict)
        return FromSCMSCM()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Trait:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Trait':
        assert isinstance(obj, dict)
        return Trait()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class FromSCM:
    id: Optional[str] = None
    """The name of the SCM head/trunk/branch/tag that this source provides."""
    name: Optional[str] = None
    scm: Optional[FromSCMSCM] = None
    traits: Optional[List[Trait]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'FromSCM':
        assert isinstance(obj, dict)
        id = from_union([from_str, from_none], obj.get("id"))
        name = from_union([from_str, from_none], obj.get("name"))
        scm = from_union([FromSCMSCM.from_dict, from_none], obj.get("scm"))
        traits = from_union([lambda x: from_list(Trait.from_dict, x), from_none], obj.get("traits"))
        return FromSCM(id, name, scm, traits)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_union([from_str, from_none], self.id)
        result["name"] = from_union([from_str, from_none], self.name)
        result["scm"] = from_union([lambda x: to_class(FromSCMSCM, x), from_none], self.scm)
        result["traits"] = from_union([lambda x: from_list(lambda x: to_class(Trait, x), x), from_none], self.traits)
        return result


@dataclass
class Branch:
    name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Branch':
        assert isinstance(obj, dict)
        name = from_union([from_str, from_none], obj.get("name"))
        return Branch(name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_union([from_str, from_none], self.name)
        return result


@dataclass
class Browser:
    """Defines the repository browser that displays changes detected by the git plugin."""
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Browser':
        assert isinstance(obj, dict)
        return Browser()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class GitBuildChooser:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GitBuildChooser':
        assert isinstance(obj, dict)
        return GitBuildChooser()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Extension:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Extension':
        assert isinstance(obj, dict)
        return Extension()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class SubmoduleCFG:
    """List of branches to build.
    Jenkins jobs are most effective when each job builds only a single branch.
    When a single job builds multiple branches, the changelog comparisons between branches
    often show no changes or incorrect changes.
    """
    branches: Optional[str] = None
    submodule_name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SubmoduleCFG':
        assert isinstance(obj, dict)
        branches = from_union([from_str, from_none], obj.get("branches"))
        submodule_name = from_union([from_str, from_none], obj.get("submoduleName"))
        return SubmoduleCFG(branches, submodule_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["branches"] = from_union([from_str, from_none], self.branches)
        result["submoduleName"] = from_union([from_str, from_none], self.submodule_name)
        return result


@dataclass
class UserRemoteConfig:
    credentials_id: Optional[str] = None
    name: Optional[str] = None
    refspec: Optional[str] = None
    url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'UserRemoteConfig':
        assert isinstance(obj, dict)
        credentials_id = from_union([from_str, from_none], obj.get("credentialsId"))
        name = from_union([from_str, from_none], obj.get("name"))
        refspec = from_union([from_str, from_none], obj.get("refspec"))
        url = from_union([from_str, from_none], obj.get("url"))
        return UserRemoteConfig(credentials_id, name, refspec, url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["credentialsId"] = from_union([from_str, from_none], self.credentials_id)
        result["name"] = from_union([from_str, from_none], self.name)
        result["refspec"] = from_union([from_str, from_none], self.refspec)
        result["url"] = from_union([from_str, from_none], self.url)
        return result


@dataclass
class UnclassifiedGit:
    """List of branches to build.
    Jenkins jobs are most effective when each job builds only a single branch.
    When a single job builds multiple branches, the changelog comparisons between branches
    often show no changes or incorrect changes.
    """
    branches: Optional[List[Branch]] = None
    """Defines the repository browser that displays changes detected by the git plugin."""
    browser: Optional[Browser] = None
    build_chooser: Optional[GitBuildChooser] = None
    """Removed facility that was intended to test combinations of git submodule versions.
    Removed in git plugin 4.6.0.
    Ignores the user provided value and always uses false as its value.
    """
    do_generate_submodule_configurations: Optional[bool] = None
    """Extensions add new behavior or modify existing plugin behavior for different uses.
    Extensions help users more precisely tune plugin behavior to meet their needs.
    
    
    Extensions include:
    
    
    Clone extensions modify the git operations that retrieve remote changes into the agent
    workspace.
    The extensions can adjust the amount of history retrieved, how long the retrieval is
    allowed to run, and other retrieval details.
    
    
    Checkout extensions modify the git operations that place files in the workspace from the
    git repository on the agent.
    The extensions can adjust the maximum duration of the checkout operation, the use and
    behavior of git submodules, the location of the workspace on the disc, and
    more.
    
    
    Changelog extensions adapt the source code difference calculations for different
    cases.
    
    
    Tagging extensions allow the plugin to apply tags in the current
    workspace.
    
    
    Build initiation extensions control the conditions that start a build.
    They can ignore notifications of a change or force a deeper evaluation of the commits
    when polling.
    
    
    Merge extensions can optionally merge changes from other branches into the current branch
    of the agent workspace.
    They control the source branch for the merge and the options applied to the merge.
    """
    extensions: Optional[List[Extension]] = None
    """Absolute path to the git executable.
    
    
    This is different from other Jenkins tool definitions.
    Rather than providing the directory that contains the executable, you must provide the
    complete path to the executable.
    Setting '/usr/bin/git' would be correct, while setting '/usr/bin/' is not correct.
    """
    git_tool: Optional[str] = None
    """Removed facility that was intended to test combinations of git submodule versions.
    Removed in git plugin 4.6.0.
    Ignores the user provided value(s) and always uses empty values.
    """
    submodule_cfg: Optional[List[SubmoduleCFG]] = None
    """Specify the repository to track. This can be a URL or a local file path.
    Note that for super-projects (repositories with submodules), only a local file
    path or a complete URL is valid.  The following are examples of valid git URLs.
    
    ssh://git@github.com/github/git.git
    git@github.com:github/git.git (short notation for ssh protocol)
    ssh://user@other.host.com/~/repos/R.git (to access the repos/R.git
    repository in the user's home directory)
    https://github.com/github/git.git
    
    
    If the repository is a super-project, the
    location from which to clone submodules is dependent on whether the repository
    is bare or non-bare (i.e. has a working directory).
    
    If the super-project is bare, the location of the submodules will be
    taken from .gitmodules.
    If the super-project is not bare, it is assumed that the
    repository has each of its submodules cloned and checked out appropriately.
    Thus, the submodules will be taken directly from a path like
    ${SUPER_PROJECT_URL}/${SUBMODULE}, rather than relying on
    information from .gitmodules.
    
    
    For a local URL/path to a super-project,
    git rev-parse --is-bare-repository
    is used to detect whether the super-project is bare or not.
    
    For a remote URL to a super-project, the ending of the URL determines whether
    a bare or non-bare repository is assumed:
    
    If the remote URL ends with /.git, a non-bare repository is
    assumed.
    If the remote URL does NOT end with /.git, a bare
    repository is assumed.
    """
    user_remote_configs: Optional[List[UserRemoteConfig]] = None

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedGit':
        assert isinstance(obj, dict)
        branches = from_union([lambda x: from_list(Branch.from_dict, x), from_none], obj.get("branches"))
        browser = from_union([Browser.from_dict, from_none], obj.get("browser"))
        build_chooser = from_union([GitBuildChooser.from_dict, from_none], obj.get("buildChooser"))
        do_generate_submodule_configurations = from_union([from_bool, from_none], obj.get("doGenerateSubmoduleConfigurations"))
        extensions = from_union([lambda x: from_list(Extension.from_dict, x), from_none], obj.get("extensions"))
        git_tool = from_union([from_str, from_none], obj.get("gitTool"))
        submodule_cfg = from_union([lambda x: from_list(SubmoduleCFG.from_dict, x), from_none], obj.get("submoduleCfg"))
        user_remote_configs = from_union([lambda x: from_list(UserRemoteConfig.from_dict, x), from_none], obj.get("userRemoteConfigs"))
        return UnclassifiedGit(branches, browser, build_chooser, do_generate_submodule_configurations, extensions, git_tool, submodule_cfg, user_remote_configs)

    def to_dict(self) -> dict:
        result: dict = {}
        result["branches"] = from_union([lambda x: from_list(lambda x: to_class(Branch, x), x), from_none], self.branches)
        result["browser"] = from_union([lambda x: to_class(Browser, x), from_none], self.browser)
        result["buildChooser"] = from_union([lambda x: to_class(GitBuildChooser, x), from_none], self.build_chooser)
        result["doGenerateSubmoduleConfigurations"] = from_union([from_bool, from_none], self.do_generate_submodule_configurations)
        result["extensions"] = from_union([lambda x: from_list(lambda x: to_class(Extension, x), x), from_none], self.extensions)
        result["gitTool"] = from_union([from_str, from_none], self.git_tool)
        result["submoduleCfg"] = from_union([lambda x: from_list(lambda x: to_class(SubmoduleCFG, x), x), from_none], self.submodule_cfg)
        result["userRemoteConfigs"] = from_union([lambda x: from_list(lambda x: to_class(UserRemoteConfig, x), x), from_none], self.user_remote_configs)
        return result


@dataclass
class GitBlit:
    """Specify the name of the project in GitBlit."""
    project_name: Optional[str] = None
    """Specify the root URL serving this repository."""
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GitBlit':
        assert isinstance(obj, dict)
        project_name = from_union([from_str, from_none], obj.get("projectName"))
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return GitBlit(project_name, repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["projectName"] = from_union([from_str, from_none], self.project_name)
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class GitBranchDiscovery:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GitBranchDiscovery':
        assert isinstance(obj, dict)
        return GitBranchDiscovery()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class GitLab:
    """Specify the major and minor version of GitLab you use (such as 9.1). If you
    don't specify a version, a modern version of GitLab (>= 8.0) is assumed.
    """
    version: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GitLab':
        assert isinstance(obj, dict)
        version = from_union([from_str, from_none], obj.get("version"))
        return GitLab(version)

    def to_dict(self) -> dict:
        result: dict = {}
        result["version"] = from_union([from_str, from_none], self.version)
        return result


@dataclass
class GitLFSPull:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GitLFSPull':
        assert isinstance(obj, dict)
        return GitLFSPull()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class GitList:
    """Specify the root URL serving this repository (such as http://gitlistserver:port/REPO/)."""
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GitList':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return GitList(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class GitRepositoryBrowser:
    gitiles: Any
    c_git: Any
    git_web: Any
    git_list: Any
    git_blit_repository_browser: Any
    gitorious_web: Any
    view_git_web: Any
    redmine_web: Any
    bitbucket_web: Any
    tfs2013: Any
    phabricator: Any
    gogs_git: Any
    fisheye: Any
    bitbucket_server: Any
    git_lab: Any
    rhode_code: Any
    github_web: Any
    assembla_web: Any
    kiln_git: Any
    stash: Any

    @staticmethod
    def from_dict(obj: Any) -> 'GitRepositoryBrowser':
        assert isinstance(obj, dict)
        gitiles = obj.get("gitiles")
        c_git = obj.get("cGit")
        git_web = obj.get("gitWeb")
        git_list = obj.get("gitList")
        git_blit_repository_browser = obj.get("gitBlitRepositoryBrowser")
        gitorious_web = obj.get("gitoriousWeb")
        view_git_web = obj.get("viewGitWeb")
        redmine_web = obj.get("redmineWeb")
        bitbucket_web = obj.get("bitbucketWeb")
        tfs2013 = obj.get("tfs2013")
        phabricator = obj.get("phabricator")
        gogs_git = obj.get("gogsGit")
        fisheye = obj.get("fisheye")
        bitbucket_server = obj.get("bitbucketServer")
        git_lab = obj.get("gitLab")
        rhode_code = obj.get("rhodeCode")
        github_web = obj.get("githubWeb")
        assembla_web = obj.get("assemblaWeb")
        kiln_git = obj.get("kilnGit")
        stash = obj.get("stash")
        return GitRepositoryBrowser(gitiles, c_git, git_web, git_list, git_blit_repository_browser, gitorious_web, view_git_web, redmine_web, bitbucket_web, tfs2013, phabricator, gogs_git, fisheye, bitbucket_server, git_lab, rhode_code, github_web, assembla_web, kiln_git, stash)

    def to_dict(self) -> dict:
        result: dict = {}
        result["gitiles"] = self.gitiles
        result["cGit"] = self.c_git
        result["gitWeb"] = self.git_web
        result["gitList"] = self.git_list
        result["gitBlitRepositoryBrowser"] = self.git_blit_repository_browser
        result["gitoriousWeb"] = self.gitorious_web
        result["viewGitWeb"] = self.view_git_web
        result["redmineWeb"] = self.redmine_web
        result["bitbucketWeb"] = self.bitbucket_web
        result["tfs2013"] = self.tfs2013
        result["phabricator"] = self.phabricator
        result["gogsGit"] = self.gogs_git
        result["fisheye"] = self.fisheye
        result["bitbucketServer"] = self.bitbucket_server
        result["gitLab"] = self.git_lab
        result["rhodeCode"] = self.rhode_code
        result["githubWeb"] = self.github_web
        result["assemblaWeb"] = self.assembla_web
        result["kilnGit"] = self.kiln_git
        result["stash"] = self.stash
        return result


@dataclass
class GitSCM:
    add_git_tag_action: Optional[bool] = None
    allow_second_fetch: Optional[bool] = None
    create_account_based_on_email: Optional[bool] = None
    disable_git_tool_chooser: Optional[bool] = None
    global_config_email: Optional[str] = None
    global_config_name: Optional[str] = None
    hide_credentials: Optional[bool] = None
    show_entire_commit_summary_in_changes: Optional[bool] = None
    use_existing_account_with_same_email: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GitSCM':
        assert isinstance(obj, dict)
        add_git_tag_action = from_union([from_bool, from_none], obj.get("addGitTagAction"))
        allow_second_fetch = from_union([from_bool, from_none], obj.get("allowSecondFetch"))
        create_account_based_on_email = from_union([from_bool, from_none], obj.get("createAccountBasedOnEmail"))
        disable_git_tool_chooser = from_union([from_bool, from_none], obj.get("disableGitToolChooser"))
        global_config_email = from_union([from_str, from_none], obj.get("globalConfigEmail"))
        global_config_name = from_union([from_str, from_none], obj.get("globalConfigName"))
        hide_credentials = from_union([from_bool, from_none], obj.get("hideCredentials"))
        show_entire_commit_summary_in_changes = from_union([from_bool, from_none], obj.get("showEntireCommitSummaryInChanges"))
        use_existing_account_with_same_email = from_union([from_bool, from_none], obj.get("useExistingAccountWithSameEmail"))
        return GitSCM(add_git_tag_action, allow_second_fetch, create_account_based_on_email, disable_git_tool_chooser, global_config_email, global_config_name, hide_credentials, show_entire_commit_summary_in_changes, use_existing_account_with_same_email)

    def to_dict(self) -> dict:
        result: dict = {}
        result["addGitTagAction"] = from_union([from_bool, from_none], self.add_git_tag_action)
        result["allowSecondFetch"] = from_union([from_bool, from_none], self.allow_second_fetch)
        result["createAccountBasedOnEmail"] = from_union([from_bool, from_none], self.create_account_based_on_email)
        result["disableGitToolChooser"] = from_union([from_bool, from_none], self.disable_git_tool_chooser)
        result["globalConfigEmail"] = from_union([from_str, from_none], self.global_config_email)
        result["globalConfigName"] = from_union([from_str, from_none], self.global_config_name)
        result["hideCredentials"] = from_union([from_bool, from_none], self.hide_credentials)
        result["showEntireCommitSummaryInChanges"] = from_union([from_bool, from_none], self.show_entire_commit_summary_in_changes)
        result["useExistingAccountWithSameEmail"] = from_union([from_bool, from_none], self.use_existing_account_with_same_email)
        return result


@dataclass
class GitSCMExtension:
    build_chooser_setting: Any
    pre_build_merge: Any
    build_single_revision_only: Any
    git_lfs_pull: Any
    path_restriction: Any
    scm_name: Any
    author_in_changelog: Any
    checkout_option: Any
    user_identity: Any
    disable_remote_poll: Any
    ignore_notify_commit: Any
    wipe_workspace: Any
    user_exclusion: Any
    prune_stale_branch: Any
    submodule_option: Any
    sparse_checkout_paths: Any
    per_build_tag: Any
    clean_checkout: Any
    changelog_to_branch: Any
    clone_option: Any
    relative_target_directory: Any
    clean_before_checkout: Any
    message_exclusion: Any
    prune_tags: Any
    local_branch: Any

    @staticmethod
    def from_dict(obj: Any) -> 'GitSCMExtension':
        assert isinstance(obj, dict)
        build_chooser_setting = obj.get("buildChooserSetting")
        pre_build_merge = obj.get("preBuildMerge")
        build_single_revision_only = obj.get("buildSingleRevisionOnly")
        git_lfs_pull = obj.get("gitLFSPull")
        path_restriction = obj.get("pathRestriction")
        scm_name = obj.get("scmName")
        author_in_changelog = obj.get("authorInChangelog")
        checkout_option = obj.get("checkoutOption")
        user_identity = obj.get("userIdentity")
        disable_remote_poll = obj.get("disableRemotePoll")
        ignore_notify_commit = obj.get("ignoreNotifyCommit")
        wipe_workspace = obj.get("wipeWorkspace")
        user_exclusion = obj.get("userExclusion")
        prune_stale_branch = obj.get("pruneStaleBranch")
        submodule_option = obj.get("submoduleOption")
        sparse_checkout_paths = obj.get("sparseCheckoutPaths")
        per_build_tag = obj.get("perBuildTag")
        clean_checkout = obj.get("cleanCheckout")
        changelog_to_branch = obj.get("changelogToBranch")
        clone_option = obj.get("cloneOption")
        relative_target_directory = obj.get("relativeTargetDirectory")
        clean_before_checkout = obj.get("cleanBeforeCheckout")
        message_exclusion = obj.get("messageExclusion")
        prune_tags = obj.get("pruneTags")
        local_branch = obj.get("localBranch")
        return GitSCMExtension(build_chooser_setting, pre_build_merge, build_single_revision_only, git_lfs_pull, path_restriction, scm_name, author_in_changelog, checkout_option, user_identity, disable_remote_poll, ignore_notify_commit, wipe_workspace, user_exclusion, prune_stale_branch, submodule_option, sparse_checkout_paths, per_build_tag, clean_checkout, changelog_to_branch, clone_option, relative_target_directory, clean_before_checkout, message_exclusion, prune_tags, local_branch)

    def to_dict(self) -> dict:
        result: dict = {}
        result["buildChooserSetting"] = self.build_chooser_setting
        result["preBuildMerge"] = self.pre_build_merge
        result["buildSingleRevisionOnly"] = self.build_single_revision_only
        result["gitLFSPull"] = self.git_lfs_pull
        result["pathRestriction"] = self.path_restriction
        result["scmName"] = self.scm_name
        result["authorInChangelog"] = self.author_in_changelog
        result["checkoutOption"] = self.checkout_option
        result["userIdentity"] = self.user_identity
        result["disableRemotePoll"] = self.disable_remote_poll
        result["ignoreNotifyCommit"] = self.ignore_notify_commit
        result["wipeWorkspace"] = self.wipe_workspace
        result["userExclusion"] = self.user_exclusion
        result["pruneStaleBranch"] = self.prune_stale_branch
        result["submoduleOption"] = self.submodule_option
        result["sparseCheckoutPaths"] = self.sparse_checkout_paths
        result["perBuildTag"] = self.per_build_tag
        result["cleanCheckout"] = self.clean_checkout
        result["changelogToBranch"] = self.changelog_to_branch
        result["cloneOption"] = self.clone_option
        result["relativeTargetDirectory"] = self.relative_target_directory
        result["cleanBeforeCheckout"] = self.clean_before_checkout
        result["messageExclusion"] = self.message_exclusion
        result["pruneTags"] = self.prune_tags
        result["localBranch"] = self.local_branch
        return result


@dataclass
class GitTagDiscovery:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GitTagDiscovery':
        assert isinstance(obj, dict)
        return GitTagDiscovery()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class GitWeb:
    """Specify the root URL serving this repository (such as
    https://github.com/jenkinsci/jenkins.git).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GitWeb':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return GitWeb(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class GithubWeb:
    """Specify the HTTP URL for this repository's GitHub page (such as
    https://github.com/jquery/jquery).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GithubWeb':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return GithubWeb(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class Gitiles:
    """Specify the root URL serving this repository (such as https://gwt.googlesource.com/gwt/)."""
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Gitiles':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return Gitiles(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class GitoriousWeb:
    """Specify the root URL serving this repository (such as
    https://gitorious.org/gitorious/mainline).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GitoriousWeb':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return GitoriousWeb(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class GlobalBuildDiscarderStrategy:
    simple_build_discarder: Any
    job_build_discarder: Any

    @staticmethod
    def from_dict(obj: Any) -> 'GlobalBuildDiscarderStrategy':
        assert isinstance(obj, dict)
        simple_build_discarder = obj.get("simpleBuildDiscarder")
        job_build_discarder = obj.get("jobBuildDiscarder")
        return GlobalBuildDiscarderStrategy(simple_build_discarder, job_build_discarder)

    def to_dict(self) -> dict:
        result: dict = {}
        result["simpleBuildDiscarder"] = self.simple_build_discarder
        result["jobBuildDiscarder"] = self.job_build_discarder
        return result


@dataclass
class GlobalDefaultFlowDurabilityLevel:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GlobalDefaultFlowDurabilityLevel':
        assert isinstance(obj, dict)
        return GlobalDefaultFlowDurabilityLevel()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class GlobalLibraries:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'GlobalLibraries':
        assert isinstance(obj, dict)
        return GlobalLibraries()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class GogsGit:
    """Specify the root URL serving this repository (such as
    http://gogs.example.com:port/username/some-repo-url.git).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'GogsGit':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return GogsGit(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class HeadRegexFilter:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2017, CloudBees, Inc.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    A Java regular expression to
    restrict the names. Names that do not match the supplied regular expression will be
    ignored.
    NOTE: this filter will be applied to all branch like things, including change requests
    """
    regex: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'HeadRegexFilter':
        assert isinstance(obj, dict)
        regex = from_union([from_str, from_none], obj.get("regex"))
        return HeadRegexFilter(regex)

    def to_dict(self) -> dict:
        result: dict = {}
        result["regex"] = from_union([from_str, from_none], self.regex)
        return result


@dataclass
class HeadWildcardFilter:
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2017, CloudBees, Inc.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    Space-separated list of name patterns to ignore even if matched by the includes list.
    For example: release alpha-* beta-*
    NOTE: this filter will be applied to all branch like things, including change requests
    """
    excludes: Optional[str] = None
    """<!--
    ~ The MIT License
    ~
    ~ Copyright (c) 2017, CloudBees, Inc.
    ~
    ~ Permission is hereby granted, free of charge, to any person obtaining a copy
    ~ of this software and associated documentation files (the "Software"), to deal
    ~ in the Software without restriction, including without limitation the rights
    ~ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    ~ copies of the Software, and to permit persons to whom the Software is
    ~ furnished to do so, subject to the following conditions:
    ~
    ~ The above copyright notice and this permission notice shall be included in
    ~ all copies or substantial portions of the Software.
    ~
    ~ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    ~ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    ~ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    ~ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    ~ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    ~ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    ~ THE SOFTWARE.
    -->
    
    Space-separated list of name patterns to consider.
    You may use * as a wildcard; for example: master release*
    NOTE: this filter will be applied to all branch like things, including change requests
    """
    includes: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'HeadWildcardFilter':
        assert isinstance(obj, dict)
        excludes = from_union([from_str, from_none], obj.get("excludes"))
        includes = from_union([from_str, from_none], obj.get("includes"))
        return HeadWildcardFilter(excludes, includes)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludes"] = from_union([from_str, from_none], self.excludes)
        result["includes"] = from_union([from_str, from_none], self.includes)
        return result


@dataclass
class IgnoreNotifyCommit:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'IgnoreNotifyCommit':
        assert isinstance(obj, dict)
        return IgnoreNotifyCommit()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Inverse:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Inverse':
        assert isinstance(obj, dict)
        return Inverse()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JobBuildDiscarder:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'JobBuildDiscarder':
        assert isinstance(obj, dict)
        return JobBuildDiscarder()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class JunitTestResultStorage:
    file: Any

    @staticmethod
    def from_dict(obj: Any) -> 'JunitTestResultStorage':
        assert isinstance(obj, dict)
        file = obj.get("file")
        return JunitTestResultStorage(file)

    def to_dict(self) -> dict:
        result: dict = {}
        result["file"] = self.file
        return result


@dataclass
class KilnGit:
    """Specify the root URL serving this repository (such as
    https://khanacademy.kilnhg.com/Code/Website/Group/webapp).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'KilnGit':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return KilnGit(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class LegacySCMSCM:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LegacySCMSCM':
        assert isinstance(obj, dict)
        return LegacySCMSCM()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LegacySCM:
    """A relative path from the root of the SCM to the root of the library.
    Leave this field blank if the root of the library is the root of the SCM.
    Note that ".." is not permitted as a path component to avoid security issues.
    """
    library_path: Optional[str] = None
    scm: Optional[LegacySCMSCM] = None

    @staticmethod
    def from_dict(obj: Any) -> 'LegacySCM':
        assert isinstance(obj, dict)
        library_path = from_union([from_str, from_none], obj.get("libraryPath"))
        scm = from_union([LegacySCMSCM.from_dict, from_none], obj.get("scm"))
        return LegacySCM(library_path, scm)

    def to_dict(self) -> dict:
        result: dict = {}
        result["libraryPath"] = from_union([from_str, from_none], self.library_path)
        result["scm"] = from_union([lambda x: to_class(LegacySCMSCM, x), from_none], self.scm)
        return result


@dataclass
class LibraryRetriever:
    modern_scm: Any
    legacy_scm: Any

    @staticmethod
    def from_dict(obj: Any) -> 'LibraryRetriever':
        assert isinstance(obj, dict)
        modern_scm = obj.get("modernSCM")
        legacy_scm = obj.get("legacySCM")
        return LibraryRetriever(modern_scm, legacy_scm)

    def to_dict(self) -> dict:
        result: dict = {}
        result["modernSCM"] = self.modern_scm
        result["legacySCM"] = self.legacy_scm
        return result


@dataclass
class LocalBranch:
    local_branch: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'LocalBranch':
        assert isinstance(obj, dict)
        local_branch = from_union([from_str, from_none], obj.get("localBranch"))
        return LocalBranch(local_branch)

    def to_dict(self) -> dict:
        result: dict = {}
        result["localBranch"] = from_union([from_str, from_none], self.local_branch)
        return result


@dataclass
class Location:
    """Notification e-mails from Jenkins to project owners will be sent
    with this address in the from header. This can be just
    "foo@acme.org" or it could be something like "Jenkins Daemon &lt;foo@acme.org>"
    """
    admin_address: Optional[str] = None
    """Optionally specify the HTTP address of the Jenkins installation, such
    as http://yourhost.yourdomain/jenkins/. This value is used to
    let Jenkins know how to refer to itself, ie. to display images or to
    create links in emails.
    
    
    This is necessary because Jenkins cannot reliably detect such a URL
    from within itself.
    """
    url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Location':
        assert isinstance(obj, dict)
        admin_address = from_union([from_str, from_none], obj.get("adminAddress"))
        url = from_union([from_str, from_none], obj.get("url"))
        return Location(admin_address, url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["adminAddress"] = from_union([from_str, from_none], self.admin_address)
        result["url"] = from_union([from_str, from_none], self.url)
        return result


@dataclass
class LockableResourcesManager:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'LockableResourcesManager':
        assert isinstance(obj, dict)
        return LockableResourcesManager()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class LogRotator:
    artifact_days_to_keep_str: Optional[str] = None
    artifact_num_to_keep_str: Optional[str] = None
    days_to_keep_str: Optional[str] = None
    num_to_keep_str: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'LogRotator':
        assert isinstance(obj, dict)
        artifact_days_to_keep_str = from_union([from_str, from_none], obj.get("artifactDaysToKeepStr"))
        artifact_num_to_keep_str = from_union([from_str, from_none], obj.get("artifactNumToKeepStr"))
        days_to_keep_str = from_union([from_str, from_none], obj.get("daysToKeepStr"))
        num_to_keep_str = from_union([from_str, from_none], obj.get("numToKeepStr"))
        return LogRotator(artifact_days_to_keep_str, artifact_num_to_keep_str, days_to_keep_str, num_to_keep_str)

    def to_dict(self) -> dict:
        result: dict = {}
        result["artifactDaysToKeepStr"] = from_union([from_str, from_none], self.artifact_days_to_keep_str)
        result["artifactNumToKeepStr"] = from_union([from_str, from_none], self.artifact_num_to_keep_str)
        result["daysToKeepStr"] = from_union([from_str, from_none], self.days_to_keep_str)
        result["numToKeepStr"] = from_union([from_str, from_none], self.num_to_keep_str)
        return result


@dataclass
class Authentication:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Authentication':
        assert isinstance(obj, dict)
        return Authentication()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UnclassifiedMailer:
    authentication: Optional[Authentication] = None
    charset: Optional[str] = None
    default_suffix: Optional[str] = None
    reply_to_address: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[str] = None
    use_ssl: Optional[bool] = None
    use_tls: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedMailer':
        assert isinstance(obj, dict)
        authentication = from_union([Authentication.from_dict, from_none], obj.get("authentication"))
        charset = from_union([from_str, from_none], obj.get("charset"))
        default_suffix = from_union([from_str, from_none], obj.get("defaultSuffix"))
        reply_to_address = from_union([from_str, from_none], obj.get("replyToAddress"))
        smtp_host = from_union([from_str, from_none], obj.get("smtpHost"))
        smtp_port = from_union([from_str, from_none], obj.get("smtpPort"))
        use_ssl = from_union([from_bool, from_none], obj.get("useSsl"))
        use_tls = from_union([from_bool, from_none], obj.get("useTls"))
        return UnclassifiedMailer(authentication, charset, default_suffix, reply_to_address, smtp_host, smtp_port, use_ssl, use_tls)

    def to_dict(self) -> dict:
        result: dict = {}
        result["authentication"] = from_union([lambda x: to_class(Authentication, x), from_none], self.authentication)
        result["charset"] = from_union([from_str, from_none], self.charset)
        result["defaultSuffix"] = from_union([from_str, from_none], self.default_suffix)
        result["replyToAddress"] = from_union([from_str, from_none], self.reply_to_address)
        result["smtpHost"] = from_union([from_str, from_none], self.smtp_host)
        result["smtpPort"] = from_union([from_str, from_none], self.smtp_port)
        result["useSsl"] = from_union([from_bool, from_none], self.use_ssl)
        result["useTls"] = from_union([from_bool, from_none], self.use_tls)
        return result


@dataclass
class MessageExclusion:
    """If set, and Jenkins is set to poll for changes, Jenkins will ignore any revisions
    committed with message matched to
    Pattern when determining
    if a build needs to be triggered. This can be used to exclude commits done by the build
    itself from triggering another build,
    assuming the build server commits the change with a distinct message.
    Exclusion uses Pattern
    matching
    
    .*\[maven-release-plugin\].*
    The example above illustrates that if only revisions with "[maven-release-plugin]"
    message in first comment line
    have been committed to the SCM a build will not occur.
    
    You can create more complex patterns using embedded flag expressions.
    (?s).*FOO.*
    This example will search FOO message in all comment lines.
    """
    excluded_message: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'MessageExclusion':
        assert isinstance(obj, dict)
        excluded_message = from_union([from_str, from_none], obj.get("excludedMessage"))
        return MessageExclusion(excluded_message)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludedMessage"] = from_union([from_str, from_none], self.excluded_message)
        return result


@dataclass
class ModernSCMSCM:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'ModernSCMSCM':
        assert isinstance(obj, dict)
        return ModernSCMSCM()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class ModernSCM:
    """A relative path from the root of the SCM to the root of the library.
    Leave this field blank if the root of the library is the root of the SCM.
    Note that ".." is not permitted as a path component to avoid security issues.
    """
    library_path: Optional[str] = None
    scm: Optional[ModernSCMSCM] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ModernSCM':
        assert isinstance(obj, dict)
        library_path = from_union([from_str, from_none], obj.get("libraryPath"))
        scm = from_union([ModernSCMSCM.from_dict, from_none], obj.get("scm"))
        return ModernSCM(library_path, scm)

    def to_dict(self) -> dict:
        result: dict = {}
        result["libraryPath"] = from_union([from_str, from_none], self.library_path)
        result["scm"] = from_union([lambda x: to_class(ModernSCMSCM, x), from_none], self.scm)
        return result


@dataclass
class UnclassifiedMyView:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedMyView':
        assert isinstance(obj, dict)
        return UnclassifiedMyView()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class NodeProperties:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'NodeProperties':
        assert isinstance(obj, dict)
        return NodeProperties()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UnclassifiedNone:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedNone':
        assert isinstance(obj, dict)
        return UnclassifiedNone()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PathRestriction:
    """Each exclusion uses java regular expression pattern matching,
    and must be separated by a new line.
    
    
    myapp/src/main/web/.*\.html
    myapp/src/main/web/.*\.jpeg
    myapp/src/main/web/.*\.gif
    
    The example above illustrates that if only html/jpeg/gif files have been committed to
    the SCM a build will not occur.
    """
    excluded_regions: Optional[str] = None
    """Each inclusion uses java regular expression pattern matching,
    and must be separated by a new line.
    An empty list implies that everything is included.
    
    
    myapp/src/main/web/.*\.html
    myapp/src/main/web/.*\.jpeg
    myapp/src/main/web/.*\.gif
    
    The example above illustrates that a build will only occur, if html/jpeg/gif files
    have been committed to the SCM. Exclusions take precedence over inclusions, if there is
    an overlap between included and excluded regions.
    """
    included_regions: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'PathRestriction':
        assert isinstance(obj, dict)
        excluded_regions = from_union([from_str, from_none], obj.get("excludedRegions"))
        included_regions = from_union([from_str, from_none], obj.get("includedRegions"))
        return PathRestriction(excluded_regions, included_regions)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludedRegions"] = from_union([from_str, from_none], self.excluded_regions)
        result["includedRegions"] = from_union([from_str, from_none], self.included_regions)
        return result


@dataclass
class PerBuildTag:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PerBuildTag':
        assert isinstance(obj, dict)
        return PerBuildTag()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Phabricator:
    """Specify the repository name in phabricator (such as the foo part of
    phabricator.example.com/diffusion/foo/browse).
    """
    repo: Optional[str] = None
    """Specify the phabricator instance root URL (such as http://phabricator.example.com)."""
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Phabricator':
        assert isinstance(obj, dict)
        repo = from_union([from_str, from_none], obj.get("repo"))
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return Phabricator(repo, repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repo"] = from_union([from_str, from_none], self.repo)
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class Plugin:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Plugin':
        assert isinstance(obj, dict)
        return Plugin()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PollSCM:
    polling_thread_count: Optional[int] = None

    @staticmethod
    def from_dict(obj: Any) -> 'PollSCM':
        assert isinstance(obj, dict)
        polling_thread_count = from_union([from_int, from_none], obj.get("pollingThreadCount"))
        return PollSCM(polling_thread_count)

    def to_dict(self) -> dict:
        result: dict = {}
        result["pollingThreadCount"] = from_union([from_int, from_none], self.polling_thread_count)
        return result


@dataclass
class PreBuildMergeOptions:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PreBuildMergeOptions':
        assert isinstance(obj, dict)
        return PreBuildMergeOptions()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PreBuildMerge:
    options: Optional[PreBuildMergeOptions] = None

    @staticmethod
    def from_dict(obj: Any) -> 'PreBuildMerge':
        assert isinstance(obj, dict)
        options = from_union([PreBuildMergeOptions.from_dict, from_none], obj.get("options"))
        return PreBuildMerge(options)

    def to_dict(self) -> dict:
        result: dict = {}
        result["options"] = from_union([lambda x: to_class(PreBuildMergeOptions, x), from_none], self.options)
        return result


@dataclass
class PrimaryBranchHealthMetric:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PrimaryBranchHealthMetric':
        assert isinstance(obj, dict)
        return PrimaryBranchHealthMetric()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UnclassifiedProjectNamingStrategy:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedProjectNamingStrategy':
        assert isinstance(obj, dict)
        return UnclassifiedProjectNamingStrategy()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PruneStaleBranch:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'PruneStaleBranch':
        assert isinstance(obj, dict)
        return PruneStaleBranch()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class PruneTags:
    prune_tags: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'PruneTags':
        assert isinstance(obj, dict)
        prune_tags = from_union([from_bool, from_none], obj.get("pruneTags"))
        return PruneTags(prune_tags)

    def to_dict(self) -> dict:
        result: dict = {}
        result["pruneTags"] = from_union([from_bool, from_none], self.prune_tags)
        return result


@dataclass
class QuietPeriod:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'QuietPeriod':
        assert isinstance(obj, dict)
        return QuietPeriod()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class RedmineWeb:
    """Specify the root URL serving this repository (such as
    http://SERVER/PATH/projects/PROJECT/repository).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'RedmineWeb':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return RedmineWeb(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class RelativeTargetDirectory:
    """Specify a local directory (relative to the workspace root)
    where the Git repository will be checked out. If left empty, the workspace root itself
    will be used.
    
    This extension should not be used in Jenkins Pipeline (either declarative or scripted).
    Jenkins Pipeline already provides standard techniques for checkout to a subdirectory.
    Use ws and
    dir
    in Jenkins Pipeline rather than this extension.
    """
    relative_target_dir: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'RelativeTargetDirectory':
        assert isinstance(obj, dict)
        relative_target_dir = from_union([from_str, from_none], obj.get("relativeTargetDir"))
        return RelativeTargetDirectory(relative_target_dir)

    def to_dict(self) -> dict:
        result: dict = {}
        result["relativeTargetDir"] = from_union([from_str, from_none], self.relative_target_dir)
        return result


@dataclass
class ResourceRoot:
    """Jenkins serves many files that are potentially created by untrusted users, such as files
    in project workspaces or archived artifacts.
    When no resource root URL is defined, Jenkins will serve these files with the HTTP header
    Content-Security-Policy ("CSP").
    By default it is set to a value that disables many modern web features to prevent
    cross-site scripting (XSS) and other attacks on Jenkins users accessing these files.
    While the specific value for the CSP header is user configurable (and can even be
    disabled), doing so is a trade-off between security and functionality.
    
    
    If the resource root URL is defined, Jenkins will instead redirect requests for
    user-created resource files to URLs starting with the URL configured here.
    These URLs will not set the CSP header, allowing JavaScript and similar features to
    work.
    For this option to work as expected, the following constraints and considerations
    apply:
    
    
    The resource root URL must be a valid alternative choice for the Jenkins URL for requests
    to be processed correctly.
    The Jenkins URL must be set and it must be different from this resource root URL (in
    fact, a different host name is required).
    
    Once set, Jenkins will only serve resource URL requests via the resource root
    URL.
    All other requests will get HTTP 404 Not Found responses.
    
    
    
    Once this URL has been set up correctly, Jenkins will redirect requests to workspaces,
    archived artifacts, and similar collections of usually user-generated content to URLs
    starting with the resource root URL.
    Instead of a path like job/name_here/ws, resource URLs will contain a token encoding that
    path, the user for which the URL was created, and when it was created.
    These resource URLs access static files as if the user for which they were created would
    access them:
    If the user’s permission to access these files is removed, the corresponding resource
    URLs will not work anymore either.
    These URLs are accessible to anyone without authentication until they expire, so sharing
    these URLs is akin to sharing the files directly.
    
    Security considerations
    Authentication
    
    Resource URLs do not require authentication (users will not have a valid session for the
    resource root URL).
    Sharing a resource URL with another user, even one lacking Overall/Read permission for
    Jenkins, will grant that user access to these files until the URLs expire.
    
    Expiration
    
    Resource URLs expire after 30 minutes by default.
    Expired resource URLs will redirect users to their equivalent Jenkins URLs, so that the
    user can reauthenticate, if necessary, and then be redirected back to a new resource URL
    that will be valid for another 30 minutes.
    This will generally be transparent to the user if they have a valid Jenkins session.
    Otherwise, they will need to authenticate with Jenkins again.
    However, when browsing pages with HTML frames, like Javadoc sites, the login form cannot
    appear in a frame.
    In these cases, users will need to reload the top-level frame to make the login form
    appear.
    
    
    To change how quickly resource URLs expire, set the system property
    jenkins.security.ResourceDomainRootAction.validForMinutes to the desired value in
    minutes.
    Earlier expiration might make it harder to use these URLs, while later expiration
    increases the likelihood of unauthorized users gaining access through URLs shared with
    them by authorized users.
    
    Authenticity
    
    Resource URLs encode the URL, the user for which they were created, and their creation
    timestamp.
    Additionally, this string contains an HMAC to ensure the authenticity of the URL.
    This prevents attackers from forging URLs that would grant them access to resource files
    as if they were another user.
    """
    url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ResourceRoot':
        assert isinstance(obj, dict)
        url = from_union([from_str, from_none], obj.get("url"))
        return ResourceRoot(url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["url"] = from_union([from_str, from_none], self.url)
        return result


@dataclass
class RhodeCode:
    """Specify the HTTP URL for this repository's RhodeCode page (such as
    http://rhodecode.mydomain.com:5000/projects/PROJECT/repos/REPO/).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'RhodeCode':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return RhodeCode(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class SCMSource:
    from_scm: Any
    git: Any

    @staticmethod
    def from_dict(obj: Any) -> 'SCMSource':
        assert isinstance(obj, dict)
        from_scm = obj.get("fromScm")
        git = obj.get("git")
        return SCMSource(from_scm, git)

    def to_dict(self) -> dict:
        result: dict = {}
        result["fromScm"] = self.from_scm
        result["git"] = self.git
        return result


@dataclass
class SCMSourceTrait:
    clean_after_checkout_trait: Any
    prune_stale_branch_trait: Any
    git_lfs_pull_trait: Any
    ignore_on_push_notification_trait: Any
    git_browser: Any
    ref_specs: Any
    clone_option_trait: Any
    sparse_checkout_paths_trait: Any
    user_identity_trait: Any
    head_wildcard_filter: Any
    submodule_option_trait: Any
    author_in_changelog_trait: Any
    git_tool: Any
    checkout_option_trait: Any
    wipe_workspace_trait: Any
    local_branch_trait: Any
    git_branch_discovery: Any
    clean_before_checkout_trait: Any
    prune_stale_tag_trait: Any
    discover_other_refs_trait: Any
    git_tag_discovery: Any
    head_regex_filter: Any
    remote_name: Any

    @staticmethod
    def from_dict(obj: Any) -> 'SCMSourceTrait':
        assert isinstance(obj, dict)
        clean_after_checkout_trait = obj.get("cleanAfterCheckoutTrait")
        prune_stale_branch_trait = obj.get("pruneStaleBranchTrait")
        git_lfs_pull_trait = obj.get("gitLFSPullTrait")
        ignore_on_push_notification_trait = obj.get("ignoreOnPushNotificationTrait")
        git_browser = obj.get("gitBrowser")
        ref_specs = obj.get("refSpecs")
        clone_option_trait = obj.get("cloneOptionTrait")
        sparse_checkout_paths_trait = obj.get("sparseCheckoutPathsTrait")
        user_identity_trait = obj.get("userIdentityTrait")
        head_wildcard_filter = obj.get("headWildcardFilter")
        submodule_option_trait = obj.get("submoduleOptionTrait")
        author_in_changelog_trait = obj.get("authorInChangelogTrait")
        git_tool = obj.get("gitTool")
        checkout_option_trait = obj.get("checkoutOptionTrait")
        wipe_workspace_trait = obj.get("wipeWorkspaceTrait")
        local_branch_trait = obj.get("localBranchTrait")
        git_branch_discovery = obj.get("gitBranchDiscovery")
        clean_before_checkout_trait = obj.get("cleanBeforeCheckoutTrait")
        prune_stale_tag_trait = obj.get("pruneStaleTagTrait")
        discover_other_refs_trait = obj.get("discoverOtherRefsTrait")
        git_tag_discovery = obj.get("gitTagDiscovery")
        head_regex_filter = obj.get("headRegexFilter")
        remote_name = obj.get("remoteName")
        return SCMSourceTrait(clean_after_checkout_trait, prune_stale_branch_trait, git_lfs_pull_trait, ignore_on_push_notification_trait, git_browser, ref_specs, clone_option_trait, sparse_checkout_paths_trait, user_identity_trait, head_wildcard_filter, submodule_option_trait, author_in_changelog_trait, git_tool, checkout_option_trait, wipe_workspace_trait, local_branch_trait, git_branch_discovery, clean_before_checkout_trait, prune_stale_tag_trait, discover_other_refs_trait, git_tag_discovery, head_regex_filter, remote_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["cleanAfterCheckoutTrait"] = self.clean_after_checkout_trait
        result["pruneStaleBranchTrait"] = self.prune_stale_branch_trait
        result["gitLFSPullTrait"] = self.git_lfs_pull_trait
        result["ignoreOnPushNotificationTrait"] = self.ignore_on_push_notification_trait
        result["gitBrowser"] = self.git_browser
        result["refSpecs"] = self.ref_specs
        result["cloneOptionTrait"] = self.clone_option_trait
        result["sparseCheckoutPathsTrait"] = self.sparse_checkout_paths_trait
        result["userIdentityTrait"] = self.user_identity_trait
        result["headWildcardFilter"] = self.head_wildcard_filter
        result["submoduleOptionTrait"] = self.submodule_option_trait
        result["authorInChangelogTrait"] = self.author_in_changelog_trait
        result["gitTool"] = self.git_tool
        result["checkoutOptionTrait"] = self.checkout_option_trait
        result["wipeWorkspaceTrait"] = self.wipe_workspace_trait
        result["localBranchTrait"] = self.local_branch_trait
        result["gitBranchDiscovery"] = self.git_branch_discovery
        result["cleanBeforeCheckoutTrait"] = self.clean_before_checkout_trait
        result["pruneStaleTagTrait"] = self.prune_stale_tag_trait
        result["discoverOtherRefsTrait"] = self.discover_other_refs_trait
        result["gitTagDiscovery"] = self.git_tag_discovery
        result["headRegexFilter"] = self.head_regex_filter
        result["remoteName"] = self.remote_name
        return result


@dataclass
class UnclassifiedSCM:
    git: Any
    none: Any

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedSCM':
        assert isinstance(obj, dict)
        git = obj.get("git")
        none = obj.get("none")
        return UnclassifiedSCM(git, none)

    def to_dict(self) -> dict:
        result: dict = {}
        result["git"] = self.git
        result["none"] = self.none
        return result


@dataclass
class SCMName:
    name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SCMName':
        assert isinstance(obj, dict)
        name = from_union([from_str, from_none], obj.get("name"))
        return SCMName(name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["name"] = from_union([from_str, from_none], self.name)
        return result


@dataclass
class SCMRetryCount:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'SCMRetryCount':
        assert isinstance(obj, dict)
        return SCMRetryCount()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class Shell:
    shell: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Shell':
        assert isinstance(obj, dict)
        shell = from_union([from_str, from_none], obj.get("shell"))
        return Shell(shell)

    def to_dict(self) -> dict:
        result: dict = {}
        result["shell"] = from_union([from_str, from_none], self.shell)
        return result


@dataclass
class Discarder:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'Discarder':
        assert isinstance(obj, dict)
        return Discarder()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class SimpleBuildDiscarder:
    discarder: Optional[Discarder] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SimpleBuildDiscarder':
        assert isinstance(obj, dict)
        discarder = from_union([Discarder.from_dict, from_none], obj.get("discarder"))
        return SimpleBuildDiscarder(discarder)

    def to_dict(self) -> dict:
        result: dict = {}
        result["discarder"] = from_union([lambda x: to_class(Discarder, x), from_none], self.discarder)
        return result


@dataclass
class Stash:
    """Specify the HTTP URL for this repository's Stash page (such as
    http://stash.mydomain.com:7990/projects/PROJECT/repos/REPO/).
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Stash':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return Stash(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class SubmoduleConfig:
    """Removed in git plugin 4.6.0."""
    branches: Optional[str] = None
    """Removed in git plugin 4.6.0."""
    submodule_name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SubmoduleConfig':
        assert isinstance(obj, dict)
        branches = from_union([from_str, from_none], obj.get("branches"))
        submodule_name = from_union([from_str, from_none], obj.get("submoduleName"))
        return SubmoduleConfig(branches, submodule_name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["branches"] = from_union([from_str, from_none], self.branches)
        result["submoduleName"] = from_union([from_str, from_none], self.submodule_name)
        return result


@dataclass
class SubmoduleOption:
    """Set shallow clone depth, so that git will only download recent history of the project,
    saving time and disk space when you just want to access the latest commits of a
    repository.
    """
    depth: Optional[int] = None
    """By disabling support for submodules you can still keep using basic
    git plugin functionality and just have Jenkins to ignore submodules
    completely as if they didn't exist.
    """
    disable_submodules: Optional[bool] = None
    """Use credentials from the default remote of the parent project."""
    parent_credentials: Optional[bool] = None
    """Retrieve all submodules recursively
    
    (uses '--recursive' option which requires git>=1.6.5)
    """
    recursive_submodules: Optional[bool] = None
    """Specify a folder containing a repository that will be used by Git as a reference during
    clone operations.
    This option will be ignored if the folder is not available on the controller or agent
    where the clone is being executed.
    To prepare a reference folder with multiple subprojects, create a bare git repository and
    add all the remote urls then perform a fetch:
    
    git init --bare
    git remote add SubProject1 https://gitrepo.com/subproject1
    git remote add SubProject2 https://gitrepo.com/subproject2
    git fetch --all
    """
    reference: Optional[str] = None
    """Perform shallow clone, so that git will not download the history of the project,
    saving time and disk space when you just want to access the latest version of a
    repository.
    """
    shallow: Optional[bool] = None
    """Specify the number of threads that will be used to update submodules.
    If unspecified, the command line git default thread count is used.
    """
    threads: Optional[int] = None
    """Specify a timeout (in minutes) for submodules operations.
    This option overrides the default timeout of 10 minutes.
    You can change the global git timeout via the property
    org.jenkinsci.plugins.gitclient.Git.timeOut (see JENKINS-11286).
    Note that property should be set on both controller and agent to have effect (see
    JENKINS-22547).
    """
    timeout: Optional[int] = None
    """Retrieve the tip of the configured branch in .gitmodules
    
    (Uses '--remote' option which requires git>=1.8.2)
    """
    tracking_submodules: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'SubmoduleOption':
        assert isinstance(obj, dict)
        depth = from_union([from_int, from_none], obj.get("depth"))
        disable_submodules = from_union([from_bool, from_none], obj.get("disableSubmodules"))
        parent_credentials = from_union([from_bool, from_none], obj.get("parentCredentials"))
        recursive_submodules = from_union([from_bool, from_none], obj.get("recursiveSubmodules"))
        reference = from_union([from_str, from_none], obj.get("reference"))
        shallow = from_union([from_bool, from_none], obj.get("shallow"))
        threads = from_union([from_int, from_none], obj.get("threads"))
        timeout = from_union([from_int, from_none], obj.get("timeout"))
        tracking_submodules = from_union([from_bool, from_none], obj.get("trackingSubmodules"))
        return SubmoduleOption(depth, disable_submodules, parent_credentials, recursive_submodules, reference, shallow, threads, timeout, tracking_submodules)

    def to_dict(self) -> dict:
        result: dict = {}
        result["depth"] = from_union([from_int, from_none], self.depth)
        result["disableSubmodules"] = from_union([from_bool, from_none], self.disable_submodules)
        result["parentCredentials"] = from_union([from_bool, from_none], self.parent_credentials)
        result["recursiveSubmodules"] = from_union([from_bool, from_none], self.recursive_submodules)
        result["reference"] = from_union([from_str, from_none], self.reference)
        result["shallow"] = from_union([from_bool, from_none], self.shallow)
        result["threads"] = from_union([from_int, from_none], self.threads)
        result["timeout"] = from_union([from_int, from_none], self.timeout)
        result["trackingSubmodules"] = from_union([from_bool, from_none], self.tracking_submodules)
        return result


@dataclass
class TFS2013Git:
    """Either the name of the remote whose URL should be used, or the URL of this
    module in TFS (such as http://fisheye6.cenqua.com/tfs/PROJECT/_git/REPO/).
    If empty (default), the URL of the "origin" repository is used.
    If TFS is also used as the repository server, this can usually be left blank.
    """
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'TFS2013Git':
        assert isinstance(obj, dict)
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return TFS2013Git(repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class Timestamper:
    """When checked, timestamps will be enabled for all Pipeline builds.
    There is no need to use the timestamps {…} step in Scripted,
    or the timestamps() option in Declarative.
    """
    all_pipelines: Optional[bool] = None
    """<!--
    The MIT License
    
    Copyright (c) 2013 Steven G. Brown
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
    -->
    
    
    The elapsed time format defines how the timestamps will be rendered when the elapsed time
    option has been selected.
    The Commons Lang DurationFormatUtils pattern is used.
    
    Default is: '&lt;b&gt;'HH:mm:ss.S'&lt;/b&gt; '.
    """
    elapsed_time_format: Optional[str] = None
    """<!--
    The MIT License
    
    Copyright (c) 2012 Frederik Fromm
    Copyright (c) 2013 Steven G. Brown
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
    -->
    
    
    The system clock time format defines how the timestamps will be rendered.
    The JDK SimpleDateFormat pattern is used.
    
    Default is: '&lt;b&gt;'HH:mm:ss'&lt;/b&gt; '
    For a more detailed format use: yyyy-MM-dd HH:mm:ss.SSS' | '.
    """
    system_time_format: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Timestamper':
        assert isinstance(obj, dict)
        all_pipelines = from_union([from_bool, from_none], obj.get("allPipelines"))
        elapsed_time_format = from_union([from_str, from_none], obj.get("elapsedTimeFormat"))
        system_time_format = from_union([from_str, from_none], obj.get("systemTimeFormat"))
        return Timestamper(all_pipelines, elapsed_time_format, system_time_format)

    def to_dict(self) -> dict:
        result: dict = {}
        result["allPipelines"] = from_union([from_bool, from_none], self.all_pipelines)
        result["elapsedTimeFormat"] = from_union([from_str, from_none], self.elapsed_time_format)
        result["systemTimeFormat"] = from_union([from_str, from_none], self.system_time_format)
        return result


@dataclass
class UsageStatistics:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UsageStatistics':
        assert isinstance(obj, dict)
        return UsageStatistics()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class UserExclusion:
    """If set, and Jenkins is set to poll for changes, Jenkins will ignore any revisions
    committed by users in this list when determining if a build needs to be triggered. This
    can be used to exclude commits done by the build itself from triggering another build,
    assuming the build server commits the change with a distinct SCM user.
    
    Using this behaviour will preclude the faster git ls-remote polling mechanism, forcing
    polling to require a workspace thus sometimes triggering unwanted builds, as if you had
    selected the Force polling using workspace extension as well.
    Each exclusion uses exact string comparison and must be separated by a new line.
    User names are only excluded if they exactly match one of the names in this list.
    
    auto_build_user
    The example above illustrates that if only revisions by "auto_build_user" have been
    committed to the SCM a build will not occur.
    """
    excluded_users: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'UserExclusion':
        assert isinstance(obj, dict)
        excluded_users = from_union([from_str, from_none], obj.get("excludedUsers"))
        return UserExclusion(excluded_users)

    def to_dict(self) -> dict:
        result: dict = {}
        result["excludedUsers"] = from_union([from_str, from_none], self.excluded_users)
        return result


@dataclass
class UserIdentity:
    """If given, "GIT_COMMITTER_EMAIL=[this]" and "GIT_AUTHOR_EMAIL=[this]" are set for builds.
    This overrides whatever is in the global settings.
    """
    email: Optional[str] = None
    """If given, "GIT_COMMITTER_NAME=[this]" and "GIT_AUTHOR_NAME=[this]" are set for builds.
    This overrides whatever is in the global settings.
    """
    name: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'UserIdentity':
        assert isinstance(obj, dict)
        email = from_union([from_str, from_none], obj.get("email"))
        name = from_union([from_str, from_none], obj.get("name"))
        return UserIdentity(email, name)

    def to_dict(self) -> dict:
        result: dict = {}
        result["email"] = from_union([from_str, from_none], self.email)
        result["name"] = from_union([from_str, from_none], self.name)
        return result


@dataclass
class ViewGitWeb:
    """Specify the name of the project in ViewGit (e.g. scripts, scuttle etc. from
    http://code.fealdia.org/viewgit/).
    """
    project_name: Optional[str] = None
    """Specify the root URL serving this repository (such as http://code.fealdia.org/viewgit/)."""
    repo_url: Optional[str] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ViewGitWeb':
        assert isinstance(obj, dict)
        project_name = from_union([from_str, from_none], obj.get("projectName"))
        repo_url = from_union([from_str, from_none], obj.get("repoUrl"))
        return ViewGitWeb(project_name, repo_url)

    def to_dict(self) -> dict:
        result: dict = {}
        result["projectName"] = from_union([from_str, from_none], self.project_name)
        result["repoUrl"] = from_union([from_str, from_none], self.repo_url)
        return result


@dataclass
class UnclassifiedViewsTabBar:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedViewsTabBar':
        assert isinstance(obj, dict)
        return UnclassifiedViewsTabBar()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class WipeWorkspace:
    pass

    @staticmethod
    def from_dict(obj: Any) -> 'WipeWorkspace':
        assert isinstance(obj, dict)
        return WipeWorkspace()

    def to_dict(self) -> dict:
        result: dict = {}
        return result


@dataclass
class WorstChildHealthMetric:
    """Controls whether items within sub-folders will be considered as contributing to the
    health of this folder.
    """
    recursive: Optional[bool] = None

    @staticmethod
    def from_dict(obj: Any) -> 'WorstChildHealthMetric':
        assert isinstance(obj, dict)
        recursive = from_union([from_bool, from_none], obj.get("recursive"))
        return WorstChildHealthMetric(recursive)

    def to_dict(self) -> dict:
        result: dict = {}
        result["recursive"] = from_union([from_bool, from_none], self.recursive)
        return result


@dataclass
class ConfigurationBaseForTheUnclassifiedClassifier:
    artifact_manager_factory: Any
    empty: Optional[Unclassified] = None
    administrative_monitors_configuration: Optional[AdministrativeMonitorsConfiguration] = None
    ancestry: Optional[Ancestry] = None
    artifact_manager: Optional[ArtifactManager] = None
    assembla_web: Optional[AssemblaWeb] = None
    author_in_changelog: Optional[AuthorInChangelog] = None
    bitbucket_server: Optional[BitbucketServer] = None
    bitbucket_web: Optional[BitbucketWeb] = None
    build_chooser: Optional[UnclassifiedBuildChooser] = None
    build_chooser_setting: Optional[BuildChooserSetting] = None
    build_discarder: Optional[BuildDiscarder] = None
    build_discarders: Optional[BuildDiscarders] = None
    build_single_revision_only: Optional[BuildSingleRevisionOnly] = None
    build_step_operation: Optional[BuildStepOperation] = None
    built_in_node: Optional[BuiltInNode] = None
    cas_c_global_config: Optional[CasCGlobalConfig] = None
    c_git: Optional[CGit] = None
    changelog_to_branch: Optional[ChangelogToBranch] = None
    checkout_option: Optional[CheckoutOption] = None
    clean_before_checkout: Optional[CleanBeforeCheckout] = None
    clean_checkout: Optional[CleanCheckout] = None
    clone_option: Optional[CloneOption] = None
    default: Optional[Default] = None
    default_folder_configuration: Optional[DefaultFolderConfiguration] = None
    default_view: Optional[DefaultView] = None
    disable_remote_poll: Optional[DisableRemotePoll] = None
    env_vars_filter: Optional[EnvVarsFilter] = None
    file: Optional[UnclassifiedFile] = None
    fingerprints: Optional[Fingerprints] = None
    fingerprint_storage: Optional[FingerprintStorage] = None
    fisheye_git: Optional[FisheyeGit] = None
    folder_health_metric: Optional[FolderHealthMetric] = None
    from_scm: Optional[FromSCM] = None
    git: Optional[UnclassifiedGit] = None
    git_blit: Optional[GitBlit] = None
    git_branch_discovery: Optional[GitBranchDiscovery] = None
    github_web: Optional[GithubWeb] = None
    gitiles: Optional[Gitiles] = None
    git_lab: Optional[GitLab] = None
    git_lfs_pull: Optional[GitLFSPull] = None
    git_list: Optional[GitList] = None
    gitorious_web: Optional[GitoriousWeb] = None
    git_repository_browser: Optional[GitRepositoryBrowser] = None
    git_scm: Optional[GitSCM] = None
    git_scm_extension: Optional[GitSCMExtension] = None
    git_tag_discovery: Optional[GitTagDiscovery] = None
    git_web: Optional[GitWeb] = None
    global_build_discarder_strategy: Optional[GlobalBuildDiscarderStrategy] = None
    global_default_flow_durability_level: Optional[GlobalDefaultFlowDurabilityLevel] = None
    global_libraries: Optional[GlobalLibraries] = None
    gogs_git: Optional[GogsGit] = None
    head_regex_filter: Optional[HeadRegexFilter] = None
    head_wildcard_filter: Optional[HeadWildcardFilter] = None
    ignore_notify_commit: Optional[IgnoreNotifyCommit] = None
    inverse: Optional[Inverse] = None
    job_build_discarder: Optional[JobBuildDiscarder] = None
    junit_test_result_storage: Optional[JunitTestResultStorage] = None
    kiln_git: Optional[KilnGit] = None
    legacy_scm: Optional[LegacySCM] = None
    library_retriever: Optional[LibraryRetriever] = None
    local_branch: Optional[LocalBranch] = None
    location: Optional[Location] = None
    lockable_resources_manager: Optional[LockableResourcesManager] = None
    log_rotator: Optional[LogRotator] = None
    mailer: Optional[UnclassifiedMailer] = None
    message_exclusion: Optional[MessageExclusion] = None
    modern_scm: Optional[ModernSCM] = None
    my_view: Optional[UnclassifiedMyView] = None
    node_properties: Optional[NodeProperties] = None
    none: Optional[UnclassifiedNone] = None
    path_restriction: Optional[PathRestriction] = None
    per_build_tag: Optional[PerBuildTag] = None
    phabricator: Optional[Phabricator] = None
    plugin: Optional[Plugin] = None
    poll_scm: Optional[PollSCM] = None
    pre_build_merge: Optional[PreBuildMerge] = None
    primary_branch_health_metric: Optional[PrimaryBranchHealthMetric] = None
    project_naming_strategy: Optional[UnclassifiedProjectNamingStrategy] = None
    prune_stale_branch: Optional[PruneStaleBranch] = None
    prune_tags: Optional[PruneTags] = None
    quiet_period: Optional[QuietPeriod] = None
    redmine_web: Optional[RedmineWeb] = None
    relative_target_directory: Optional[RelativeTargetDirectory] = None
    resource_root: Optional[ResourceRoot] = None
    rhode_code: Optional[RhodeCode] = None
    scm: Optional[UnclassifiedSCM] = None
    scm_name: Optional[SCMName] = None
    scm_retry_count: Optional[SCMRetryCount] = None
    s_cm_source: Optional[SCMSource] = None
    s_cm_source_trait: Optional[SCMSourceTrait] = None
    shell: Optional[Shell] = None
    simple_build_discarder: Optional[SimpleBuildDiscarder] = None
    stash: Optional[Stash] = None
    submodule_config: Optional[SubmoduleConfig] = None
    submodule_option: Optional[SubmoduleOption] = None
    t_fs2013_git: Optional[TFS2013Git] = None
    timestamper: Optional[Timestamper] = None
    usage_statistics: Optional[UsageStatistics] = None
    user_exclusion: Optional[UserExclusion] = None
    user_identity: Optional[UserIdentity] = None
    view_git_web: Optional[ViewGitWeb] = None
    views_tab_bar: Optional[UnclassifiedViewsTabBar] = None
    wipe_workspace: Optional[WipeWorkspace] = None
    worst_child_health_metric: Optional[WorstChildHealthMetric] = None

    @staticmethod
    def from_dict(obj: Any) -> 'ConfigurationBaseForTheUnclassifiedClassifier':
        assert isinstance(obj, dict)
        artifact_manager_factory = obj.get("artifactManagerFactory")
        empty = from_union([Unclassified.from_dict, from_none], obj.get(""))
        administrative_monitors_configuration = from_union([AdministrativeMonitorsConfiguration.from_dict, from_none], obj.get("administrativeMonitorsConfiguration"))
        ancestry = from_union([Ancestry.from_dict, from_none], obj.get("ancestry"))
        artifact_manager = from_union([ArtifactManager.from_dict, from_none], obj.get("artifactManager"))
        assembla_web = from_union([AssemblaWeb.from_dict, from_none], obj.get("assemblaWeb"))
        author_in_changelog = from_union([AuthorInChangelog.from_dict, from_none], obj.get("authorInChangelog"))
        bitbucket_server = from_union([BitbucketServer.from_dict, from_none], obj.get("bitbucketServer"))
        bitbucket_web = from_union([BitbucketWeb.from_dict, from_none], obj.get("bitbucketWeb"))
        build_chooser = from_union([UnclassifiedBuildChooser.from_dict, from_none], obj.get("buildChooser"))
        build_chooser_setting = from_union([BuildChooserSetting.from_dict, from_none], obj.get("buildChooserSetting"))
        build_discarder = from_union([BuildDiscarder.from_dict, from_none], obj.get("buildDiscarder"))
        build_discarders = from_union([BuildDiscarders.from_dict, from_none], obj.get("buildDiscarders"))
        build_single_revision_only = from_union([BuildSingleRevisionOnly.from_dict, from_none], obj.get("buildSingleRevisionOnly"))
        build_step_operation = from_union([BuildStepOperation.from_dict, from_none], obj.get("buildStepOperation"))
        built_in_node = from_union([BuiltInNode.from_dict, from_none], obj.get("builtInNode"))
        cas_c_global_config = from_union([CasCGlobalConfig.from_dict, from_none], obj.get("casCGlobalConfig"))
        c_git = from_union([CGit.from_dict, from_none], obj.get("cGit"))
        changelog_to_branch = from_union([ChangelogToBranch.from_dict, from_none], obj.get("changelogToBranch"))
        checkout_option = from_union([CheckoutOption.from_dict, from_none], obj.get("checkoutOption"))
        clean_before_checkout = from_union([CleanBeforeCheckout.from_dict, from_none], obj.get("cleanBeforeCheckout"))
        clean_checkout = from_union([CleanCheckout.from_dict, from_none], obj.get("cleanCheckout"))
        clone_option = from_union([CloneOption.from_dict, from_none], obj.get("cloneOption"))
        default = from_union([Default.from_dict, from_none], obj.get("default"))
        default_folder_configuration = from_union([DefaultFolderConfiguration.from_dict, from_none], obj.get("defaultFolderConfiguration"))
        default_view = from_union([DefaultView.from_dict, from_none], obj.get("defaultView"))
        disable_remote_poll = from_union([DisableRemotePoll.from_dict, from_none], obj.get("disableRemotePoll"))
        env_vars_filter = from_union([EnvVarsFilter.from_dict, from_none], obj.get("envVarsFilter"))
        file = from_union([UnclassifiedFile.from_dict, from_none], obj.get("file"))
        fingerprints = from_union([Fingerprints.from_dict, from_none], obj.get("fingerprints"))
        fingerprint_storage = from_union([FingerprintStorage.from_dict, from_none], obj.get("fingerprintStorage"))
        fisheye_git = from_union([FisheyeGit.from_dict, from_none], obj.get("fisheyeGit"))
        folder_health_metric = from_union([FolderHealthMetric.from_dict, from_none], obj.get("folderHealthMetric"))
        from_scm = from_union([FromSCM.from_dict, from_none], obj.get("fromScm"))
        git = from_union([UnclassifiedGit.from_dict, from_none], obj.get("git"))
        git_blit = from_union([GitBlit.from_dict, from_none], obj.get("gitBlit"))
        git_branch_discovery = from_union([GitBranchDiscovery.from_dict, from_none], obj.get("gitBranchDiscovery"))
        github_web = from_union([GithubWeb.from_dict, from_none], obj.get("githubWeb"))
        gitiles = from_union([Gitiles.from_dict, from_none], obj.get("gitiles"))
        git_lab = from_union([GitLab.from_dict, from_none], obj.get("gitLab"))
        git_lfs_pull = from_union([GitLFSPull.from_dict, from_none], obj.get("gitLFSPull"))
        git_list = from_union([GitList.from_dict, from_none], obj.get("gitList"))
        gitorious_web = from_union([GitoriousWeb.from_dict, from_none], obj.get("gitoriousWeb"))
        git_repository_browser = from_union([GitRepositoryBrowser.from_dict, from_none], obj.get("gitRepositoryBrowser"))
        git_scm = from_union([GitSCM.from_dict, from_none], obj.get("gitSCM"))
        git_scm_extension = from_union([GitSCMExtension.from_dict, from_none], obj.get("gitSCMExtension"))
        git_tag_discovery = from_union([GitTagDiscovery.from_dict, from_none], obj.get("gitTagDiscovery"))
        git_web = from_union([GitWeb.from_dict, from_none], obj.get("gitWeb"))
        global_build_discarder_strategy = from_union([GlobalBuildDiscarderStrategy.from_dict, from_none], obj.get("globalBuildDiscarderStrategy"))
        global_default_flow_durability_level = from_union([GlobalDefaultFlowDurabilityLevel.from_dict, from_none], obj.get("globalDefaultFlowDurabilityLevel"))
        global_libraries = from_union([GlobalLibraries.from_dict, from_none], obj.get("globalLibraries"))
        gogs_git = from_union([GogsGit.from_dict, from_none], obj.get("gogsGit"))
        head_regex_filter = from_union([HeadRegexFilter.from_dict, from_none], obj.get("headRegexFilter"))
        head_wildcard_filter = from_union([HeadWildcardFilter.from_dict, from_none], obj.get("headWildcardFilter"))
        ignore_notify_commit = from_union([IgnoreNotifyCommit.from_dict, from_none], obj.get("ignoreNotifyCommit"))
        inverse = from_union([Inverse.from_dict, from_none], obj.get("inverse"))
        job_build_discarder = from_union([JobBuildDiscarder.from_dict, from_none], obj.get("jobBuildDiscarder"))
        junit_test_result_storage = from_union([JunitTestResultStorage.from_dict, from_none], obj.get("junitTestResultStorage"))
        kiln_git = from_union([KilnGit.from_dict, from_none], obj.get("kilnGit"))
        legacy_scm = from_union([LegacySCM.from_dict, from_none], obj.get("legacySCM"))
        library_retriever = from_union([LibraryRetriever.from_dict, from_none], obj.get("libraryRetriever"))
        local_branch = from_union([LocalBranch.from_dict, from_none], obj.get("localBranch"))
        location = from_union([Location.from_dict, from_none], obj.get("location"))
        lockable_resources_manager = from_union([LockableResourcesManager.from_dict, from_none], obj.get("lockableResourcesManager"))
        log_rotator = from_union([LogRotator.from_dict, from_none], obj.get("logRotator"))
        mailer = from_union([UnclassifiedMailer.from_dict, from_none], obj.get("mailer"))
        message_exclusion = from_union([MessageExclusion.from_dict, from_none], obj.get("messageExclusion"))
        modern_scm = from_union([ModernSCM.from_dict, from_none], obj.get("modernSCM"))
        my_view = from_union([UnclassifiedMyView.from_dict, from_none], obj.get("myView"))
        node_properties = from_union([NodeProperties.from_dict, from_none], obj.get("nodeProperties"))
        none = from_union([UnclassifiedNone.from_dict, from_none], obj.get("none"))
        path_restriction = from_union([PathRestriction.from_dict, from_none], obj.get("pathRestriction"))
        per_build_tag = from_union([PerBuildTag.from_dict, from_none], obj.get("perBuildTag"))
        phabricator = from_union([Phabricator.from_dict, from_none], obj.get("phabricator"))
        plugin = from_union([Plugin.from_dict, from_none], obj.get("plugin"))
        poll_scm = from_union([PollSCM.from_dict, from_none], obj.get("pollSCM"))
        pre_build_merge = from_union([PreBuildMerge.from_dict, from_none], obj.get("preBuildMerge"))
        primary_branch_health_metric = from_union([PrimaryBranchHealthMetric.from_dict, from_none], obj.get("primaryBranchHealthMetric"))
        project_naming_strategy = from_union([UnclassifiedProjectNamingStrategy.from_dict, from_none], obj.get("projectNamingStrategy"))
        prune_stale_branch = from_union([PruneStaleBranch.from_dict, from_none], obj.get("pruneStaleBranch"))
        prune_tags = from_union([PruneTags.from_dict, from_none], obj.get("pruneTags"))
        quiet_period = from_union([QuietPeriod.from_dict, from_none], obj.get("quietPeriod"))
        redmine_web = from_union([RedmineWeb.from_dict, from_none], obj.get("redmineWeb"))
        relative_target_directory = from_union([RelativeTargetDirectory.from_dict, from_none], obj.get("relativeTargetDirectory"))
        resource_root = from_union([ResourceRoot.from_dict, from_none], obj.get("resourceRoot"))
        rhode_code = from_union([RhodeCode.from_dict, from_none], obj.get("rhodeCode"))
        scm = from_union([UnclassifiedSCM.from_dict, from_none], obj.get("scm"))
        scm_name = from_union([SCMName.from_dict, from_none], obj.get("scmName"))
        scm_retry_count = from_union([SCMRetryCount.from_dict, from_none], obj.get("scmRetryCount"))
        s_cm_source = from_union([SCMSource.from_dict, from_none], obj.get("sCMSource"))
        s_cm_source_trait = from_union([SCMSourceTrait.from_dict, from_none], obj.get("sCMSourceTrait"))
        shell = from_union([Shell.from_dict, from_none], obj.get("shell"))
        simple_build_discarder = from_union([SimpleBuildDiscarder.from_dict, from_none], obj.get("simpleBuildDiscarder"))
        stash = from_union([Stash.from_dict, from_none], obj.get("stash"))
        submodule_config = from_union([SubmoduleConfig.from_dict, from_none], obj.get("submoduleConfig"))
        submodule_option = from_union([SubmoduleOption.from_dict, from_none], obj.get("submoduleOption"))
        t_fs2013_git = from_union([TFS2013Git.from_dict, from_none], obj.get("tFS2013Git"))
        timestamper = from_union([Timestamper.from_dict, from_none], obj.get("timestamper"))
        usage_statistics = from_union([UsageStatistics.from_dict, from_none], obj.get("usageStatistics"))
        user_exclusion = from_union([UserExclusion.from_dict, from_none], obj.get("userExclusion"))
        user_identity = from_union([UserIdentity.from_dict, from_none], obj.get("userIdentity"))
        view_git_web = from_union([ViewGitWeb.from_dict, from_none], obj.get("viewGitWeb"))
        views_tab_bar = from_union([UnclassifiedViewsTabBar.from_dict, from_none], obj.get("viewsTabBar"))
        wipe_workspace = from_union([WipeWorkspace.from_dict, from_none], obj.get("wipeWorkspace"))
        worst_child_health_metric = from_union([WorstChildHealthMetric.from_dict, from_none], obj.get("worstChildHealthMetric"))
        return ConfigurationBaseForTheUnclassifiedClassifier(artifact_manager_factory, empty, administrative_monitors_configuration, ancestry, artifact_manager, assembla_web, author_in_changelog, bitbucket_server, bitbucket_web, build_chooser, build_chooser_setting, build_discarder, build_discarders, build_single_revision_only, build_step_operation, built_in_node, cas_c_global_config, c_git, changelog_to_branch, checkout_option, clean_before_checkout, clean_checkout, clone_option, default, default_folder_configuration, default_view, disable_remote_poll, env_vars_filter, file, fingerprints, fingerprint_storage, fisheye_git, folder_health_metric, from_scm, git, git_blit, git_branch_discovery, github_web, gitiles, git_lab, git_lfs_pull, git_list, gitorious_web, git_repository_browser, git_scm, git_scm_extension, git_tag_discovery, git_web, global_build_discarder_strategy, global_default_flow_durability_level, global_libraries, gogs_git, head_regex_filter, head_wildcard_filter, ignore_notify_commit, inverse, job_build_discarder, junit_test_result_storage, kiln_git, legacy_scm, library_retriever, local_branch, location, lockable_resources_manager, log_rotator, mailer, message_exclusion, modern_scm, my_view, node_properties, none, path_restriction, per_build_tag, phabricator, plugin, poll_scm, pre_build_merge, primary_branch_health_metric, project_naming_strategy, prune_stale_branch, prune_tags, quiet_period, redmine_web, relative_target_directory, resource_root, rhode_code, scm, scm_name, scm_retry_count, s_cm_source, s_cm_source_trait, shell, simple_build_discarder, stash, submodule_config, submodule_option, t_fs2013_git, timestamper, usage_statistics, user_exclusion, user_identity, view_git_web, views_tab_bar, wipe_workspace, worst_child_health_metric)

    def to_dict(self) -> dict:
        result: dict = {}
        result["artifactManagerFactory"] = self.artifact_manager_factory
        result[""] = from_union([lambda x: to_class(Unclassified, x), from_none], self.empty)
        result["administrativeMonitorsConfiguration"] = from_union([lambda x: to_class(AdministrativeMonitorsConfiguration, x), from_none], self.administrative_monitors_configuration)
        result["ancestry"] = from_union([lambda x: to_class(Ancestry, x), from_none], self.ancestry)
        result["artifactManager"] = from_union([lambda x: to_class(ArtifactManager, x), from_none], self.artifact_manager)
        result["assemblaWeb"] = from_union([lambda x: to_class(AssemblaWeb, x), from_none], self.assembla_web)
        result["authorInChangelog"] = from_union([lambda x: to_class(AuthorInChangelog, x), from_none], self.author_in_changelog)
        result["bitbucketServer"] = from_union([lambda x: to_class(BitbucketServer, x), from_none], self.bitbucket_server)
        result["bitbucketWeb"] = from_union([lambda x: to_class(BitbucketWeb, x), from_none], self.bitbucket_web)
        result["buildChooser"] = from_union([lambda x: to_class(UnclassifiedBuildChooser, x), from_none], self.build_chooser)
        result["buildChooserSetting"] = from_union([lambda x: to_class(BuildChooserSetting, x), from_none], self.build_chooser_setting)
        result["buildDiscarder"] = from_union([lambda x: to_class(BuildDiscarder, x), from_none], self.build_discarder)
        result["buildDiscarders"] = from_union([lambda x: to_class(BuildDiscarders, x), from_none], self.build_discarders)
        result["buildSingleRevisionOnly"] = from_union([lambda x: to_class(BuildSingleRevisionOnly, x), from_none], self.build_single_revision_only)
        result["buildStepOperation"] = from_union([lambda x: to_class(BuildStepOperation, x), from_none], self.build_step_operation)
        result["builtInNode"] = from_union([lambda x: to_class(BuiltInNode, x), from_none], self.built_in_node)
        result["casCGlobalConfig"] = from_union([lambda x: to_class(CasCGlobalConfig, x), from_none], self.cas_c_global_config)
        result["cGit"] = from_union([lambda x: to_class(CGit, x), from_none], self.c_git)
        result["changelogToBranch"] = from_union([lambda x: to_class(ChangelogToBranch, x), from_none], self.changelog_to_branch)
        result["checkoutOption"] = from_union([lambda x: to_class(CheckoutOption, x), from_none], self.checkout_option)
        result["cleanBeforeCheckout"] = from_union([lambda x: to_class(CleanBeforeCheckout, x), from_none], self.clean_before_checkout)
        result["cleanCheckout"] = from_union([lambda x: to_class(CleanCheckout, x), from_none], self.clean_checkout)
        result["cloneOption"] = from_union([lambda x: to_class(CloneOption, x), from_none], self.clone_option)
        result["default"] = from_union([lambda x: to_class(Default, x), from_none], self.default)
        result["defaultFolderConfiguration"] = from_union([lambda x: to_class(DefaultFolderConfiguration, x), from_none], self.default_folder_configuration)
        result["defaultView"] = from_union([lambda x: to_class(DefaultView, x), from_none], self.default_view)
        result["disableRemotePoll"] = from_union([lambda x: to_class(DisableRemotePoll, x), from_none], self.disable_remote_poll)
        result["envVarsFilter"] = from_union([lambda x: to_class(EnvVarsFilter, x), from_none], self.env_vars_filter)
        result["file"] = from_union([lambda x: to_class(UnclassifiedFile, x), from_none], self.file)
        result["fingerprints"] = from_union([lambda x: to_class(Fingerprints, x), from_none], self.fingerprints)
        result["fingerprintStorage"] = from_union([lambda x: to_class(FingerprintStorage, x), from_none], self.fingerprint_storage)
        result["fisheyeGit"] = from_union([lambda x: to_class(FisheyeGit, x), from_none], self.fisheye_git)
        result["folderHealthMetric"] = from_union([lambda x: to_class(FolderHealthMetric, x), from_none], self.folder_health_metric)
        result["fromScm"] = from_union([lambda x: to_class(FromSCM, x), from_none], self.from_scm)
        result["git"] = from_union([lambda x: to_class(UnclassifiedGit, x), from_none], self.git)
        result["gitBlit"] = from_union([lambda x: to_class(GitBlit, x), from_none], self.git_blit)
        result["gitBranchDiscovery"] = from_union([lambda x: to_class(GitBranchDiscovery, x), from_none], self.git_branch_discovery)
        result["githubWeb"] = from_union([lambda x: to_class(GithubWeb, x), from_none], self.github_web)
        result["gitiles"] = from_union([lambda x: to_class(Gitiles, x), from_none], self.gitiles)
        result["gitLab"] = from_union([lambda x: to_class(GitLab, x), from_none], self.git_lab)
        result["gitLFSPull"] = from_union([lambda x: to_class(GitLFSPull, x), from_none], self.git_lfs_pull)
        result["gitList"] = from_union([lambda x: to_class(GitList, x), from_none], self.git_list)
        result["gitoriousWeb"] = from_union([lambda x: to_class(GitoriousWeb, x), from_none], self.gitorious_web)
        result["gitRepositoryBrowser"] = from_union([lambda x: to_class(GitRepositoryBrowser, x), from_none], self.git_repository_browser)
        result["gitSCM"] = from_union([lambda x: to_class(GitSCM, x), from_none], self.git_scm)
        result["gitSCMExtension"] = from_union([lambda x: to_class(GitSCMExtension, x), from_none], self.git_scm_extension)
        result["gitTagDiscovery"] = from_union([lambda x: to_class(GitTagDiscovery, x), from_none], self.git_tag_discovery)
        result["gitWeb"] = from_union([lambda x: to_class(GitWeb, x), from_none], self.git_web)
        result["globalBuildDiscarderStrategy"] = from_union([lambda x: to_class(GlobalBuildDiscarderStrategy, x), from_none], self.global_build_discarder_strategy)
        result["globalDefaultFlowDurabilityLevel"] = from_union([lambda x: to_class(GlobalDefaultFlowDurabilityLevel, x), from_none], self.global_default_flow_durability_level)
        result["globalLibraries"] = from_union([lambda x: to_class(GlobalLibraries, x), from_none], self.global_libraries)
        result["gogsGit"] = from_union([lambda x: to_class(GogsGit, x), from_none], self.gogs_git)
        result["headRegexFilter"] = from_union([lambda x: to_class(HeadRegexFilter, x), from_none], self.head_regex_filter)
        result["headWildcardFilter"] = from_union([lambda x: to_class(HeadWildcardFilter, x), from_none], self.head_wildcard_filter)
        result["ignoreNotifyCommit"] = from_union([lambda x: to_class(IgnoreNotifyCommit, x), from_none], self.ignore_notify_commit)
        result["inverse"] = from_union([lambda x: to_class(Inverse, x), from_none], self.inverse)
        result["jobBuildDiscarder"] = from_union([lambda x: to_class(JobBuildDiscarder, x), from_none], self.job_build_discarder)
        result["junitTestResultStorage"] = from_union([lambda x: to_class(JunitTestResultStorage, x), from_none], self.junit_test_result_storage)
        result["kilnGit"] = from_union([lambda x: to_class(KilnGit, x), from_none], self.kiln_git)
        result["legacySCM"] = from_union([lambda x: to_class(LegacySCM, x), from_none], self.legacy_scm)
        result["libraryRetriever"] = from_union([lambda x: to_class(LibraryRetriever, x), from_none], self.library_retriever)
        result["localBranch"] = from_union([lambda x: to_class(LocalBranch, x), from_none], self.local_branch)
        result["location"] = from_union([lambda x: to_class(Location, x), from_none], self.location)
        result["lockableResourcesManager"] = from_union([lambda x: to_class(LockableResourcesManager, x), from_none], self.lockable_resources_manager)
        result["logRotator"] = from_union([lambda x: to_class(LogRotator, x), from_none], self.log_rotator)
        result["mailer"] = from_union([lambda x: to_class(UnclassifiedMailer, x), from_none], self.mailer)
        result["messageExclusion"] = from_union([lambda x: to_class(MessageExclusion, x), from_none], self.message_exclusion)
        result["modernSCM"] = from_union([lambda x: to_class(ModernSCM, x), from_none], self.modern_scm)
        result["myView"] = from_union([lambda x: to_class(UnclassifiedMyView, x), from_none], self.my_view)
        result["nodeProperties"] = from_union([lambda x: to_class(NodeProperties, x), from_none], self.node_properties)
        result["none"] = from_union([lambda x: to_class(UnclassifiedNone, x), from_none], self.none)
        result["pathRestriction"] = from_union([lambda x: to_class(PathRestriction, x), from_none], self.path_restriction)
        result["perBuildTag"] = from_union([lambda x: to_class(PerBuildTag, x), from_none], self.per_build_tag)
        result["phabricator"] = from_union([lambda x: to_class(Phabricator, x), from_none], self.phabricator)
        result["plugin"] = from_union([lambda x: to_class(Plugin, x), from_none], self.plugin)
        result["pollSCM"] = from_union([lambda x: to_class(PollSCM, x), from_none], self.poll_scm)
        result["preBuildMerge"] = from_union([lambda x: to_class(PreBuildMerge, x), from_none], self.pre_build_merge)
        result["primaryBranchHealthMetric"] = from_union([lambda x: to_class(PrimaryBranchHealthMetric, x), from_none], self.primary_branch_health_metric)
        result["projectNamingStrategy"] = from_union([lambda x: to_class(UnclassifiedProjectNamingStrategy, x), from_none], self.project_naming_strategy)
        result["pruneStaleBranch"] = from_union([lambda x: to_class(PruneStaleBranch, x), from_none], self.prune_stale_branch)
        result["pruneTags"] = from_union([lambda x: to_class(PruneTags, x), from_none], self.prune_tags)
        result["quietPeriod"] = from_union([lambda x: to_class(QuietPeriod, x), from_none], self.quiet_period)
        result["redmineWeb"] = from_union([lambda x: to_class(RedmineWeb, x), from_none], self.redmine_web)
        result["relativeTargetDirectory"] = from_union([lambda x: to_class(RelativeTargetDirectory, x), from_none], self.relative_target_directory)
        result["resourceRoot"] = from_union([lambda x: to_class(ResourceRoot, x), from_none], self.resource_root)
        result["rhodeCode"] = from_union([lambda x: to_class(RhodeCode, x), from_none], self.rhode_code)
        result["scm"] = from_union([lambda x: to_class(UnclassifiedSCM, x), from_none], self.scm)
        result["scmName"] = from_union([lambda x: to_class(SCMName, x), from_none], self.scm_name)
        result["scmRetryCount"] = from_union([lambda x: to_class(SCMRetryCount, x), from_none], self.scm_retry_count)
        result["sCMSource"] = from_union([lambda x: to_class(SCMSource, x), from_none], self.s_cm_source)
        result["sCMSourceTrait"] = from_union([lambda x: to_class(SCMSourceTrait, x), from_none], self.s_cm_source_trait)
        result["shell"] = from_union([lambda x: to_class(Shell, x), from_none], self.shell)
        result["simpleBuildDiscarder"] = from_union([lambda x: to_class(SimpleBuildDiscarder, x), from_none], self.simple_build_discarder)
        result["stash"] = from_union([lambda x: to_class(Stash, x), from_none], self.stash)
        result["submoduleConfig"] = from_union([lambda x: to_class(SubmoduleConfig, x), from_none], self.submodule_config)
        result["submoduleOption"] = from_union([lambda x: to_class(SubmoduleOption, x), from_none], self.submodule_option)
        result["tFS2013Git"] = from_union([lambda x: to_class(TFS2013Git, x), from_none], self.t_fs2013_git)
        result["timestamper"] = from_union([lambda x: to_class(Timestamper, x), from_none], self.timestamper)
        result["usageStatistics"] = from_union([lambda x: to_class(UsageStatistics, x), from_none], self.usage_statistics)
        result["userExclusion"] = from_union([lambda x: to_class(UserExclusion, x), from_none], self.user_exclusion)
        result["userIdentity"] = from_union([lambda x: to_class(UserIdentity, x), from_none], self.user_identity)
        result["viewGitWeb"] = from_union([lambda x: to_class(ViewGitWeb, x), from_none], self.view_git_web)
        result["viewsTabBar"] = from_union([lambda x: to_class(UnclassifiedViewsTabBar, x), from_none], self.views_tab_bar)
        result["wipeWorkspace"] = from_union([lambda x: to_class(WipeWorkspace, x), from_none], self.wipe_workspace)
        result["worstChildHealthMetric"] = from_union([lambda x: to_class(WorstChildHealthMetric, x), from_none], self.worst_child_health_metric)
        return result


@dataclass
class Coordinate:
    """Jenkins Configuration as Code"""
    configuration_as_code: Optional[ConfigurationBaseForTheConfigurationAsCodeClassifier] = None
    credentials: Optional[ConfigurationBaseForTheCredentialsClassifier] = None
    global_credentials_configuration: Optional[ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier] = None
    jenkins: Optional[ConfigurationBaseForTheJenkinsClassifier] = None
    jobs: Optional[ConfigurationBaseForTheJobsClassifier] = None
    security: Optional[ConfigurationBaseForTheSecurityClassifier] = None
    tool: Optional[ConfigurationBaseForTheToolClassifier] = None
    unclassified: Optional[ConfigurationBaseForTheUnclassifiedClassifier] = None

    @staticmethod
    def from_dict(obj: Any) -> 'Coordinate':
        assert isinstance(obj, dict)
        configuration_as_code = from_union([ConfigurationBaseForTheConfigurationAsCodeClassifier.from_dict, from_none], obj.get("configuration-as-code"))
        credentials = from_union([ConfigurationBaseForTheCredentialsClassifier.from_dict, from_none], obj.get("credentials"))
        global_credentials_configuration = from_union([ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier.from_dict, from_none], obj.get("globalCredentialsConfiguration"))
        jenkins = from_union([ConfigurationBaseForTheJenkinsClassifier.from_dict, from_none], obj.get("jenkins"))
        jobs = from_union([ConfigurationBaseForTheJobsClassifier.from_dict, from_none], obj.get("jobs"))
        security = from_union([ConfigurationBaseForTheSecurityClassifier.from_dict, from_none], obj.get("security"))
        tool = from_union([ConfigurationBaseForTheToolClassifier.from_dict, from_none], obj.get("tool"))
        unclassified = from_union([ConfigurationBaseForTheUnclassifiedClassifier.from_dict, from_none], obj.get("unclassified"))
        return Coordinate(configuration_as_code, credentials, global_credentials_configuration, jenkins, jobs, security, tool, unclassified)

    def to_dict(self) -> dict:
        result: dict = {}
        result["configuration-as-code"] = from_union([lambda x: to_class(ConfigurationBaseForTheConfigurationAsCodeClassifier, x), from_none], self.configuration_as_code)
        result["credentials"] = from_union([lambda x: to_class(ConfigurationBaseForTheCredentialsClassifier, x), from_none], self.credentials)
        result["globalCredentialsConfiguration"] = from_union([lambda x: to_class(ConfigurationBaseForTheGlobalCredentialsConfigurationClassifier, x), from_none], self.global_credentials_configuration)
        result["jenkins"] = from_union([lambda x: to_class(ConfigurationBaseForTheJenkinsClassifier, x), from_none], self.jenkins)
        result["jobs"] = from_union([lambda x: to_class(ConfigurationBaseForTheJobsClassifier, x), from_none], self.jobs)
        result["security"] = from_union([lambda x: to_class(ConfigurationBaseForTheSecurityClassifier, x), from_none], self.security)
        result["tool"] = from_union([lambda x: to_class(ConfigurationBaseForTheToolClassifier, x), from_none], self.tool)
        result["unclassified"] = from_union([lambda x: to_class(ConfigurationBaseForTheUnclassifiedClassifier, x), from_none], self.unclassified)
        return result


def coordinate_from_dict(s: Any) -> Coordinate:
    return Coordinate.from_dict(s)


def coordinate_to_dict(x: Coordinate) -> Any:
    return to_class(Coordinate, x)
