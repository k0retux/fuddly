fuddly(1)

# NAME

fuddly - cli interface to manage fuddly projects, script and everything!

# SYNOPSIS

*fuddly* -h | --help | ACTION ...

# DESCRIPTION

The fuddly cli is used by calling it with an ACTION.
They have each their own sets of arguments and
options.

# ACTIONS

*shell*
	Run the fuddly shell
*run*
	Run a project script
*new*
	Create a new data_model or project
*tool*
	Run on of fuddly's associated tools
*workspace*
	Manage the fuddly workspace
*show*
	Display the README file of a specified Project


Each of these action have a section describing their syntax and they all support
a *-h* and *--help* options to describe their use from the command line


## SHELL

*fuddly* shell [OPTIONS]

	*-f* PATH, *--fmkdb* PATH
		Path to an alternative fmkDB.db. Create it if it does not exist.

	*--external-display* 
		Display information on another terminal.

	*--quiet*
		Limit the information displayed at startup.


## RUN

*fuddly* run list | (project script_name [script_args...])

	*list*
		This option gives you a list of all the available scripts.
		
	*project*
		Name of the project from which to run the script. Using *list*
		will show all available projects.

	*script_name*
		Name of the script to launch, using *list* will show all available
		scripts for that project.

	*script_args...*
		Arguments to give to the script as if it was its command line arguments.

## NEW

*fuddly* new [OPTIONS] name

	*name*
		Name to give the created object. This should conform to python's module
		naming convention.

	*--clone* object_name
		Clone an existing data-model, project or target.

		The object_name shall be the python module name identifying the object
		to clone. Using list instead of an object name will show a list of all
		available objects that can be cloned.

		The new object will be be created in the path given by *--dest*,
		following it's default when missing from the command line.

		This option is not compatible with *--pyproject*

		NOTE: Due to the way argparse works, the *name* argument is still
		required when using the *list* argument to *--clone*.

	*--dest* PATH  
		Directory to create the object in.

		If PATH is omitted, a default value will be used.
		If *--pyproject* was used, the default PATH will be the current working directory. 
		If not, it will be the appropriate folder in the fuddly data_folder. This can be 
		either "~/.local/share/fuddly/{user_data_models, user_projects}" or 
		"~/fuddly_data/{user_data_models, user_projects}" depending on your system setup.

	*--pyproject*
		If this option is given, the object will be created in a python project
		structure. A README.md and pyproject.toml file will be added and
		partially filled. The object will be placed in the "src/" directory.

		This option is incompatible with the *--clone* option

	*--type* object_type
		Type of object to create. [dm, data-model, project:<template>]
		The "project" object should be followed by ":<template>" where
		"<template>" is the name of the project template to use.

		There are for now, 2 project template:
			- bare
			- exemple

		The "bare" template creates a barebones project with only the
		structure and a few lines of code so you can get on with your work.

		The "exemple" template is more complete, and more or less creates the
		same project as in the fuddly tutorial with comments to guide you on
		where to put what.

## TOOL

*fuddly* tool list | tool_name [tool_args...]

	*list*
		List all available tools.

	*tool_name*
		Name of the tool to launch. This should be one of the names given by the
		*list* option

	*tool_args...*
		Arguments to pass to the tool. They will be given to the script as if
		they had been passed on the command line. (argv[0] will be the name of
		the tool)


## WORKSPACE

*fuddly* workspace --show | --clean

	*--show*
		Print the path to the workspace. The path printed is wrapped in a OSC-8
		escape secquence, so terminals supporting them can make the link available
		to the user.

	*--clean* 
		Remove everything from the workspace.
		This will first list the content of the workspace, then ask for a
		confirmation before completely removing it and creating a new one.

## SHOW

*fuddly* show project_name

	*project_name*
		Name of the project whose README file is requested to be displayed.


# SEE ALSO

All of fuddly's documentation and tutorial are available at
<https://fuddly.readthedocs.io/>

# AUTHORS

Fuddly is maintained by Eric Lacombe <eric.lacombe@security-labs.org>. It has
also received contributions from various people over the years. 
For more information about fuddly development, see
<https://github.com/k0retux/fuddly>

