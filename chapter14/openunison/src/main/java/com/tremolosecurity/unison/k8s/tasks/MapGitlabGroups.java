package com.tremolosecurity.unison.k8s.tasks;

import java.util.HashMap;
import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.gitlab.provisioning.targets.GitlabUserProvider;

public class MapGitlabGroups implements CustomTask {

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        HashMap<String,Integer> groupmap = new HashMap<String,Integer>();
        for (String group : user.getGroups()) {
            if (group.startsWith("approvers-k8s-")) {
                groupmap.put(group, 40);
            } else if (group.startsWith("k8s-namespace-developer")) {
                groupmap.put(group,30);
            } else if (group.startsWith("k8s-namespace-operations")) {
                groupmap.put(group,30);
            }
        }

        request.put(GitlabUserProvider.GITLAB_GROUP_ENTITLEMENTS,groupmap);
        return true;
    }

    @Override
    public void init(WorkflowTask arg0, Map<String, Attribute> arg1) throws ProvisioningException {
        // TODO Auto-generated method stub

    }

    @Override
    public void reInit(WorkflowTask arg0) throws ProvisioningException {
        // TODO Auto-generated method stub

    }
    
}