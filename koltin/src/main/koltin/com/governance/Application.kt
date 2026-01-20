package com.governance

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.response.*
import io.ktor.server.request.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.server.plugins.callloging.*
import org.slf4j.event.Level
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.time.Instant
import java.util.*

@Serializable
data class Policy(
    val apiVersion: String,
    val kind: String = "Policy",
    val metadata: PolicyMetadata,
    val spec: PolicySpec
)

@Serializable
data class PolicyMetadata(
    val name: String,
    val description: String? = null,
    val severity: String,
    val labels: Map<String, String> = emptyMap(),
    val createdAt: String = Instant.now().toString()
)

@Serializable
data class PolicySpec(
    val targetResource: String,
    val rules: List<Rule>,
    val remediation: Remediation? = null
)

@Serializable
data class Rule(
    val name: String,
    val condition: String,
    val message: String? = null
)

@Serializable
data class Remediation(
    val type: String,
    val template: String? = null
)

@Serializable
data class EvaluationRequest(
    val resource: Map<String, Any>,
    val context: Map<String, String> = emptyMap()
)

@Serializable
data class EvaluationResponse(
    val resourceId: String,
    val evaluatedAt: String = Instant.now().toString(),
    val compliant: Boolean,
    val violations: List<Violation> = emptyList(),
    val metrics: EvaluationMetrics
)

@Serializable
data class Violation(
    val policyId: String,
    val ruleName: String,
    val message: String,
    val severity: String,
    val resource: String
)

@Serializable
data class EvaluationMetrics(
    val totalPolicies: Int,
    val evaluatedRules: Int,
    val passedRules: Int,
    val failedRules: Int,
    val evaluationTimeMs: Long
)

class PolicyRegistry {
    private val policies = mutableMapOf<String, Policy>()
    private val policyVersions = mutableMapOf<String, MutableList<Policy>>()
    
    fun register(policy: Policy): Boolean {
        val name = policy.metadata.name
        
        if (policies.containsKey(name)) {
            // Version the existing policy
            policyVersions.getOrPut(name) { mutableListOf() }.add(policies[name]!!)
        }
        
        policies[name] = policy
        return true
    }
    
    fun get(name: String): Policy? = policies[name]
    
    fun getAll(): List<Policy> = policies.values.toList()
    
    fun getVersions(name: String): List<Policy> = policyVersions[name] ?: emptyList()
    
    fun delete(name: String): Boolean {
        policies.remove(name)
        policyVersions.remove(name)
        return true
    }
}

class RulesEngine(private val registry: PolicyRegistry) {
    fun evaluate(request: EvaluationRequest): EvaluationResponse {
        val startTime = System.currentTimeMillis()
        val resource = request.resource
        val context = request.context
        
        val resourceId = resource["id"]?.toString() ?: UUID.randomUUID().toString()
        val violations = mutableListOf<Violation>()
        var evaluatedRules = 0
        var passedRules = 0
        var failedRules = 0
        
        for (policy in registry.getAll()) {
            val resourceType = resource["type"]?.toString()
            if (resourceType != policy.spec.targetResource) {
                continue
            }
            
            for (rule in policy.spec.rules) {
                evaluatedRules++
                
                val compliant = evaluateRule(rule.condition, resource, context)
                
                if (!compliant) {
                    violations.add(
                        Violation(
                            policyId = policy.metadata.name,
                            ruleName = rule.name,
                            message = rule.message ?: "Rule violation",
                            severity = policy.metadata.severity,
                            resource = resourceId
                        )
                    )
                    failedRules++
                } else {
                    passedRules++
                }
            }
        }
        
        val evaluationTime = System.currentTimeMillis() - startTime
        
        return EvaluationResponse(
            resourceId = resourceId,
            compliant = violations.isEmpty(),
            violations = violations,
            metrics = EvaluationMetrics(
                totalPolicies = registry.getAll().size,
                evaluatedRules = evaluatedRules,
                passedRules = passedRules,
                failedRules = failedRules,
                evaluationTimeMs = evaluationTime
            )
        )
    }
    
    private fun evaluateRule(condition: String, resource: Map<String, Any>, context: Map<String, String>): Boolean {
        // Simplified evaluation - in production, use a JSONPath evaluation library
        // This would parse the condition and evaluate it against the resource
        return true // Placeholder
    }
}

fun Application.module() {
    install(ContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
        })
    }
    
    install(CallLogging) {
        level = Level.INFO
    }
    
    val registry = PolicyRegistry()
    val engine = RulesEngine(registry)
    
    routing {
        route("/api/v1") {
            // Health check
            get("/health") {
                call.respond(mapOf("status" to "healthy", "timestamp" to Instant.now().toString()))
            }
            
            // Policy management
            route("/policies") {
                get {
                    val policies = registry.getAll()
                    call.respond(policies)
                }
                
                get("/{name}") {
                    val name = call.parameters["name"] ?: throw IllegalArgumentException("Name parameter is required")
                    val policy = registry.get(name)
                    
                    if (policy == null) {
                        call.respond(HttpStatusCode.NotFound, mapOf("error" to "Policy not found"))
                    } else {
                        call.respond(policy)
                    }
                }
                
                post {
                    val policy = call.receive<Policy>()
                    
                    // Validate policy
                    if (policy.kind != "Policy") {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Kind must be 'Policy'"))
                        return@post
                    }
                    
                    if (policy.metadata.severity !in listOf("low", "medium", "high", "critical")) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Invalid severity level"))
                        return@post
                    }
                    
                    val success = registry.register(policy)
                    
                    if (success) {
                        call.respond(HttpStatusCode.Created, policy)
                    } else {
                        call.respond(HttpStatusCode.InternalServerError, mapOf("error" to "Failed to register policy"))
                    }
                }
                
                delete("/{name}") {
                    val name = call.parameters["name"] ?: throw IllegalArgumentException("Name parameter is required")
                    val success = registry.delete(name)
                    
                    if (success) {
                        call.respond(HttpStatusCode.NoContent)
                    } else {
                        call.respond(HttpStatusCode.NotFound, mapOf("error" to "Policy not found"))
                    }
                }
            }
            
            // Evaluation endpoint
            post("/evaluate") {
                val request = call.receive<EvaluationRequest>()
                val response = engine.evaluate(request)
                call.respond(response)
            }
            
            // Batch evaluation
            post("/evaluate/batch") {
                val requests = call.receive<List<EvaluationRequest>>()
                val responses = requests.map { engine.evaluate(it) }
                call.respond(responses)
            }
        }
    }
}

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}
