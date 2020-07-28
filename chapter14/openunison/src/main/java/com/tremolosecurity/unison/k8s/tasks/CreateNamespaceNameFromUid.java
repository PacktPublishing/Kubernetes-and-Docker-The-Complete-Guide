package com.tremolosecurity.unison.k8s.tasks;

import java.util.Map;

import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.WorkflowTask;
import com.tremolosecurity.provisioning.util.CustomTask;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.openshiftv3.OpenShiftTarget;

public class CreateNamespaceNameFromUid implements CustomTask {
    String uidAttribute;

    @Override
    public boolean doTask(User user, Map<String, Object> request) throws ProvisioningException {
        String namespaceName = new StringBuilder("dev-user-ns-").append(OpenShiftTarget.sub2uid(user.getAttribs().get(uidAttribute).getValues().get(0))).toString();
        request.put("nameSpace",namespaceName);
        return true;

    }

    @Override
    public void init(WorkflowTask task, Map<String, Attribute> config) throws ProvisioningException {
        this.uidAttribute = config.get("uidAttribute").getValues().get(0);

    }

    @Override
    public void reInit(WorkflowTask task) throws ProvisioningException {
        

    }
    
}