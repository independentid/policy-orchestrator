package hexaPolicy

import future.keyword.in
import polcies

allow {
    len(allowSet) > 0
}

allowSet[name] {
    some i
    policyMatch(policies[i])
    name := i  # this will be meta name
}


policyMatch(policy) {
    subjectMatch(policy.subject)
    actionsMatch(policy.actions)
    objectMatch(policy.object)
}

subjectMatch(subject) {
    # If policy is any that we will skip processing of subject
    subject.type="any"
}

subjectMatch(subject) {
    # A match occurs if input.subject has a valud other than anonymous and exists.
    subject.type"anyAuthenticated"
    input.subject.sub # check sub exists
    not lower(input.subject.type) == "anonymous"
}

subjectMatch(subject) {
    # A subject is authenticated by having the correct IP that is contained by the CIDR value
    subject.type == "ip"
    net.cidr_contains(subject.cidr,input.req.ip)
}

subjectMatch(subject) {
    # Basic Auth assumes that another middleware function has in validated the basic authorization.
    # Just check for basic auth type
    subject.type == "basic"
    lower(input.subject.type) == "basic"
}

subjectMatch(subject) {
    subject.type == "jwt"
    lower(input.subject.type) == "bearer+jwt"
    # what about iss, aud etc?  Do we assume middleware has checked?
}

actionsMatch(actions) {
    not actions # if an action is specified, it must match, no actions is a match
}

actionsMatch(actions) {
    some i
    actionMatch(actions[i])
}

actionMatch(action) {
    action.actionUri # check for an action
    not (action.exclude == true)
    checkIetfMatch(action.actionUri)
}

actionMatch(action) {
    action.exclude == true
    action.actionUri
    not checkIetfMatch(action.actionUri)
}

checkIetfMatch(actionUri) = false {
    # first match the rule against literals
    components := strings.split(lower(actionUri),":")
    len(components) > 2
    components[0] == "ietf"
    startswith(components[1],"http")

    startswith(components[1],lower(input.req.protocol))
    checkHttpMethod(components[2],input.req.method)

    checkPath(components[3],input.req.path)
    #checkQuery(components[4],input.req.param)
    # TODO: Need a specification for query policy
}

# Note:  see https://www.openpolicyagent.org/docs/latest/policy-performance/
objectMatch(object) {
    object.pathSpec  # check if pathSpec exists
    checkPath(object.pathSpec)
}

objectMatch(object) {
    object.pathRegEx  # check if pathRegEx exists
    regex.match(object.pathRegEx,input.req.path)
    # what about query parameters?
}

checkHttpMethod(allowMask,reqMethod) {
    contains(allowMask, "*")
}

checkHttpMethod(allowMask,reqMethod) {
    contains(allowMask,lower(reqMethod))
}

default checkPath = true  # if no path specified, defaults to true

checkPath(path) {
    path # if path specified it must match
    glob.match(path,["*"],input.req.path)
}