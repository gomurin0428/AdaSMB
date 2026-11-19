--  The specification packages of the SPARK core (docs/platinum-design.md).
--  Each child transcribes a standard as ghost functions, citing the section,
--  and depends on nothing in the implementation: the core's postconditions
--  are written in its terms, the core's code never calls it, and
--  tests/spec_test.adb runs it on published vectors. tests/check_sources.py
--  checks that independence.
package SMB.Spec
  with Ghost, SPARK_Mode
is
end SMB.Spec;
