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

*fuddly* run --list | (script_name [script_args...])

	*--list*
		This option gives you a list of all the available scripts.
		
	*script_name*
		Name of the script to launch, the format is a python package like
		syntax.
		e.g. fuddly.projects_scripts.test

	*script_args...*
		Arguments to give to the script as if it was its command line arguments.

## NEW

*fuddly* new [OPTIONS] target name

	*target*
		Type of object to create. [dm, data-model, project:<template>]
		The "project" target shoudl be followed by ":<template>" where
		"<template>" is the name of the project template to use.

		There are for now, 2 project template:
			- skeleton
			- exemple

		The "skeleton" template creates a barebones project with only the
		structure and a few lines of code so you can get on with your work.

		The "exemple" template is more complete, and more or less creates the
		same project as in the fuddly tutorial with comments to guide you on
		where to put what.

	*name*
		Name to give the created target. This should conform to python's module
		naming convention.

	*--pyproject*
		If this option is given, the target will be create in a python project
		structure. A README.md and pyproject.toml file will be added and
		partially filled. And the target will be place in the "src/"
		directory.

	*--dest* PATH  
		Directory to create the target in.

		If *--pyproject* was used, the default value when omitted will be the current 
		working directory. If not, it will be the appropriate folder in the fuddly data_folder
		This can be either "~/.local/share/fuddly/{data_models, user_projects}" or
		"~/.fuddly/{user_data_models, user_projects}"
		depending on your system setup.

## TOOL

*fuddly* tool --list | (tool_name [tool_args...])

	*--list*
		List all available tools.

	*tool_name*
		Name of the tool to launch. This should be one of the names given by the
		*--list* option

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

# SEE ALSO

All of fuddly's documentation and tutorial are available at
<https://fuddly.readthedocs.io/>

# AUTHORS

Fuddly is maintained by Eric Lacombe <eric.lacombe@security-labs.org>. It has
also received contributions from various people over the years. 
For more information about fuddly development, see
<https://github.com/k0retux/fuddly>

