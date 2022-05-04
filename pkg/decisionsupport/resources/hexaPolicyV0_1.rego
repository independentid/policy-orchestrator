package hexaPolicy

# Rego Policy interpreter for V0.1 hexa Policy (simple policy mode)
import future.keywords.in
import data.policies

default allow = false

# Returns whether the current operation is allowed
allow {
    count(allowSet) > 0
}

# Returns the list of matching policies (by Index) based on current request
allowSet[name] {
    some i
    subjectMatch(policies[i].subject)
    actionMatch(policies[i].action)
    objectMatch(policies[i].object)
    name := sprintf("Policy#%v",[i])
}

subjectMatch(subject) {
   subject.authenticated_users[_] == "allusers"
}

subjectMatch(subject) {
   input.subject.sub
   subject.authenticated_users[_] == "allauthenticated"
}

subjectMatch(subject) {
   input.subject.sub
   lower(input.subject.sub) == lower(subject.authenticated_users[_])
}

actionMatch(action) {
    lower(action) == lower(input.req.method)
}

objectMatch(object) {
   input.req.path
   checkPath(object.resources[_])
}

checkPath(path) {
	input.req.path
    path # match will allow wildcard matches
    glob.match(path,["*"],input.req.path)
}

