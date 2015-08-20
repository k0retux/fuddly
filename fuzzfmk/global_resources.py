import os
import fuzzfmk

fuzzfmk_folder = os.path.dirname(fuzzfmk.__file__)
app_folder = os.path.dirname(os.path.dirname(fuzzfmk.__file__))

workspace_folder = app_folder + os.sep + 'workspace/'
