"""SC-14: pom.xml ${property} versions are resolved from <properties>."""

from rowan.core.version_ranges import is_exact_version
from rowan.passes.sca import SCAPass

_POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.4.2</version>
  <properties>
    <spring.version>5.3.0</spring.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>shared</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.x</groupId>
      <artifactId>unknown</artifactId>
      <version>${not.defined}</version>
    </dependency>
  </dependencies>
</project>
"""


def test_property_versions_resolved(tmp_path):
    (tmp_path / "pom.xml").write_text(_POM)
    versions = {p["name"]: p["version"] for p in SCAPass()._parse_pom_xml(tmp_path / "pom.xml")}
    assert versions["org.springframework:spring-core"] == "5.3.0"
    assert is_exact_version(versions["org.springframework:spring-core"])
    assert versions["com.example:shared"] == "1.4.2"
    assert versions["org.x:unknown"] == "${not.defined}"  # unresolved stays literal
