function Use-NSPPkiDependency {
    # Loads the sibling NSP modules the dashboard needs. The CA engine functions themselves don't
    # need them, so the module still imports on a bare host.
    Import-NSPToolkitModule -Name NSP.Bootstrap -MinimumVersion 0.1.3
    Import-NSPToolkitModule -Name NSP.Console -MinimumVersion 0.1.2
    Import-NSPToolkitModule -Name NSP.Toolkit -MinimumVersion 0.1.0
}
