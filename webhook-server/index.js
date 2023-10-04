const fs = require('fs')
const crypto = require('crypto')
const express = require('express')
const { Client } = require('@elastic/elasticsearch')

let client

const app = express()
app.use(express.json())

const HOST = process.env.GH_INSIGHTS_HOST
const CA = process.env.GH_INSIGHTS_CA_CERT
const USER = process.env.GH_INSIGHTS_USERNAME
const PASS = process.env.GH_INSIGHTS_PASSWORD
const SECRET = process.env.GITHUB_WEBHOOK_SECRET
const PORT = process.env.PORT || 3000

// Full list of common webhook events
const indices = [
    'branch_protection_rule',
    'check_run',
    'check_suite',
    'code_scanning_alert',
    'commit_comment',
    'create',
    'delete',
    'deploy_key',
    'deployment',
    'deployment_status',
    'discussion',
    'discussion_comment',
    'fork',
    'github_app_authorization',
    'gollum',
    'installation',
    'installation_repositories',
    'issue_comment',
    'issues',
    'label',
    'marketplace_purchase',
    'member',
    'membership',
    'meta',
    'milestone',
    'organization',
    'org_block',
    'package',
    'page_build',
    'ping',
    'project',
    'project_card',
    'project_column',
    'public',
    'pull_request',
    'pull_request_review',
    'pull_request_review_comment',
    'pull_request_review_thread',
    'push',
    'release',
    'repository_dispatch',
    'repository',
    'repository_import',
    'repository_vulnerability_alert',
    'security_advisory',
    'sponsorship',
    'star',
    'status',
    'team',
    'team_add',
    'watch',
    'workflow_dispatch',
    'workflow_job',
    'workflow_run'
]

async function seedIndices() {
    for (const index of indices) {
        const created = await createIndexIfNotExists(index)
        if (!created) {
            process.exit(1)
        }
    }
}

async function createIndexIfNotExists(index) {
    try {
        const response = await client.indices.exists({
            index: index
        })
        if (response === false) {
            console.log(`Creating [${index}] index`)
            await client.indices.create({
                index: index
            })
        }
        return true
    } catch (err) {
        console.error(`Error creating [${index}] index: ${err}`)
    }

    return false
}

app.post('/github/webhooks', validateWebhook, async (req, res) => {
    try {
        const id = req.headers['x-github-delivery']
        const index = req.headers['x-github-event']

        if (!indices.includes(index)) {
            const created = await createIndexIfNotExists(index)
            if (created) {
                indices.push(index)
            } else {
                res.status(500).send({message: `Error creating [${index}] index`})
                return
            }
        }

        if(index === 'workflow_job' && req.body.action === 'completed') {
            const startedAt = new Date(req.body.workflow_job.started_at)
            const completedAt = new Date(req.body.workflow_job.completed_at)
            req.body.workflow_job.duration = (completedAt - startedAt) / 1000.0
        }

        console.log(`[${index}:${id}] Adding document`)
        await client.index({
            id: id,
            index: index,
            document: req.body,
            refresh: true
        })
        console.log(`[${index}:${id}] Document added`)

        res.status(201).send({message: 'Document added'})
    } catch (err) {
        console.error(`Error indexing document: ${err.message}`)
        res.status(err.status || 413).send({message: err.message})
    }
})

app.get('/healthz', (req, res) => {
    res.status(200).send('ok')
})

function validateWebhook(req, res, next) {
    const signature = crypto
        .createHmac('sha256', SECRET)
        .update(JSON.stringify(req.body))
        .digest('hex')
    const trusted = Buffer.from(`sha256=${signature}`, 'ascii')
    const untrusted = Buffer.from(`${req.headers['x-hub-signature-256']}`, 'ascii')
    if(crypto.timingSafeEqual(trusted, untrusted)) {
        next()
    } else {
        return res.status(401).send({message: 'Invalid signature'})
    }
}

(async function main() {
    client = new Client({
        node: `https://${HOST}:9200`,
        auth: {
            username: USER,
            password: PASS
        },
        maxRetries: 5,
        requestTimeout: 60000,
        tls: {
            ca: fs.readFileSync(CA, 'utf8'),
            rejectUnauthorized: true
        }
    })

    await seedIndices()
    app.listen(PORT, () => {
        console.log(`Listening for webhooks on port ${PORT}`)
    })
})()
