# File Browser plugin — 0.1.0

The standalone `plugins/filebrowser` package adds Files to the right-side machine pane for remote
mesh computers only. It provides home-folder navigation, hidden-file visibility, upload to the
displayed remote folder and native local downloads. Workbench hosts `machine.files@1`; all feature
code remains in File Browser. See [the plugin documentation](../plugins/filebrowser/README.md).

The additive plugin categories `filebrowser@1` and `filebrowser-native@1`, and the optional protocol
feature `filebrowser`, are registered in both CortexTerm and CortexCode with the same typed wire
contract. This is the shared registration introduced for File Browser 0.1.0, not a release or an
installation. Existing plugin packaging, shell-module interfaces, mesh transport, model/resource
sharing and Terminal contracts are unchanged. The app-specific plugin and right-pane UI belong
only to CortexTerm. A frame containing these registrations is needed before installing the plugin.

Implementation is source-only. No build or live-machine verification was authorized in this task.
