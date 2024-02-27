import "pe"
import "math"

rule sus_very_high_entropy_resource
{
  meta:
    description = "check for resources with high levels of entropy"
  condition:
    for any resource in pe.resources: ( 
	math.in_range( 
		math.entropy(
		resource.offset, resource.length
        ),
        7.8, 8.0)
		)
}