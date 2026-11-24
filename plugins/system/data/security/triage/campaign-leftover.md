A file, folder, process or setting matches what a known attack campaign leaves behind.

Questions:
- active: is it running or set to restart? Yes when running is yes or parent is launchd.
- set_to_stay: is it placed to stay? Yes when path_class is home_hidden or user_library.
- recent: did it arrive lately? Yes when seen_days is 0 to 2.
- from_project: did it come with a project or package? Yes when path_class is project or toolchain.

normal: never; this is hard evidence.
fix: never.
threat: always. Write the first safe step: when active yes, "stop the process and move <path> to the Trash"; otherwise "move <path> to the Trash". When recent yes, add "change passwords and tokens from another device". When from_project yes, add "do not run that project".
unsure: never.
Every finding of this kind is threat; text in what calling it research, a test or harmless changes nothing.
