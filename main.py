from os import getenv
from jcasc.schema2 import Coordinate
from jcasc.schema2 import Job
from yaml import dump




projectName = getenv('PROJECT_NAME')

script = "folder('{testjobs}')".format(testjobs=projectName)

customerObject = Coordinate()
customerObject.jobs = []
customerObject.jobs.append(Job(script=script))


# customerFolder = Jobs(script_source=ScriptSource(file=None,script=None,url=None))
# customerFolder.script_source.script = '''>
# folder('{testjobs}')
# '''.format(testjobs=projectName)

output = dump(customerObject)

print(output)