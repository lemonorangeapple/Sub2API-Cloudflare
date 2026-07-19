<template>
  <div
    class="flex min-h-screen items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 p-4 dark:from-dark-900 dark:to-dark-800"
  >
    <div class="w-full max-w-2xl">
      <div class="mb-8 text-center">
        <div
          class="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-primary-500 to-primary-600 shadow-lg"
        >
          <Icon name="cloud" size="xl" class="text-white" />
        </div>
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white">{{ t('setup.title') }}</h1>
        <p class="mt-2 text-gray-500 dark:text-dark-400">{{ t('setup.description') }}</p>
      </div>

      <div class="mb-8">
        <div class="flex items-center justify-center">
          <template v-for="(step, index) in steps" :key="step.id">
            <div class="flex items-center">
              <div
                :class="[
                  'flex h-10 w-10 items-center justify-center rounded-full text-sm font-semibold transition-all',
                  currentStep > index
                    ? 'bg-primary-500 text-white'
                    : currentStep === index
                      ? 'bg-primary-500 text-white ring-4 ring-primary-100 dark:ring-primary-900'
                      : 'bg-gray-200 text-gray-500 dark:bg-dark-700 dark:text-dark-400'
                ]"
              >
                <Icon v-if="currentStep > index" name="check" size="md" :stroke-width="2" />
                <span v-else>{{ index + 1 }}</span>
              </div>
              <span
                class="ml-2 text-sm font-medium"
                :class="
                  currentStep >= index
                    ? 'text-gray-900 dark:text-white'
                    : 'text-gray-400 dark:text-dark-500'
                "
              >
                {{ step.title }}
              </span>
            </div>
            <div
              v-if="index < steps.length - 1"
              class="mx-3 h-0.5 w-12"
              :class="currentStep > index ? 'bg-primary-500' : 'bg-gray-200 dark:bg-dark-700'"
            ></div>
          </template>
        </div>
      </div>

      <div class="rounded-2xl bg-white p-8 shadow-xl dark:bg-dark-800">
        <div v-if="currentStep === 0" class="space-y-6">
          <div class="text-center">
            <h2 class="text-xl font-semibold text-gray-900 dark:text-white">
              {{ t('setup.cloudflare.title') }}
            </h2>
            <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
              {{ t('setup.cloudflare.description') }}
            </p>
          </div>

          <div class="grid gap-4 sm:grid-cols-2">
            <div class="rounded-xl border border-gray-200 p-4 dark:border-dark-700">
              <div class="flex items-center gap-3">
                <Icon name="database" size="lg" class="text-primary-500" />
                <div>
                  <p class="font-medium text-gray-900 dark:text-white">
                    {{ t('setup.cloudflare.database') }}
                  </p>
                  <p class="text-xs text-gray-500 dark:text-dark-400">
                    {{ t('setup.cloudflare.databaseDescription') }}
                  </p>
                </div>
              </div>
            </div>
            <div class="rounded-xl border border-gray-200 p-4 dark:border-dark-700">
              <div class="flex items-center gap-3">
                <Icon name="cloud" size="lg" class="text-primary-500" />
                <div>
                  <p class="font-medium text-gray-900 dark:text-white">
                    {{ t('setup.cloudflare.runtime') }}
                  </p>
                  <p class="text-xs text-gray-500 dark:text-dark-400">
                    {{ t('setup.cloudflare.runtimeDescription') }}
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div
            v-if="d1Ready"
            class="flex items-center gap-3 rounded-xl border border-green-200 bg-green-50 p-4 dark:border-green-800/50 dark:bg-green-900/20"
          >
            <Icon name="checkCircle" size="md" class="text-green-500" />
            <p class="text-sm text-green-700 dark:text-green-400">
              {{ t('setup.cloudflare.ready') }}
            </p>
          </div>

          <button class="btn btn-secondary w-full" :disabled="checkingEnvironment" @click="checkEnvironment">
            <svg
              v-if="checkingEnvironment"
              class="-ml-1 mr-2 h-4 w-4 animate-spin"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <Icon v-else name="refresh" size="sm" class="mr-2" />
            {{ checkingEnvironment ? t('setup.cloudflare.checking') : t('setup.cloudflare.retry') }}
          </button>
        </div>

        <div v-if="currentStep === 1" class="space-y-6">
          <div class="text-center">
            <h2 class="text-xl font-semibold text-gray-900 dark:text-white">
              {{ t('setup.admin.title') }}
            </h2>
            <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
              {{ t('setup.admin.description') }}
            </p>
          </div>

          <div>
            <label class="input-label">{{ t('setup.admin.email') }}</label>
            <input v-model="formData.admin.email" type="email" class="input" placeholder="admin@example.com" />
          </div>
          <div>
            <label class="input-label">{{ t('setup.admin.password') }}</label>
            <input
              v-model="formData.admin.password"
              type="password"
              class="input"
              :placeholder="t('setup.admin.passwordPlaceholder')"
            />
          </div>
          <div>
            <label class="input-label">{{ t('setup.admin.confirmPassword') }}</label>
            <input
              v-model="confirmPassword"
              type="password"
              class="input"
              :placeholder="t('setup.admin.confirmPasswordPlaceholder')"
            />
            <p
              v-if="confirmPassword && formData.admin.password !== confirmPassword"
              class="input-error-text"
            >
              {{ t('setup.admin.passwordMismatch') }}
            </p>
          </div>
        </div>

        <div v-if="currentStep === 2" class="space-y-6">
          <div class="text-center">
            <h2 class="text-xl font-semibold text-gray-900 dark:text-white">
              {{ t('setup.ready.title') }}
            </h2>
            <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">
              {{ t('setup.ready.description') }}
            </p>
          </div>
          <div class="space-y-4">
            <div class="rounded-xl bg-gray-50 p-4 dark:bg-dark-700">
              <h3 class="mb-2 text-sm font-medium text-gray-500 dark:text-dark-400">
                {{ t('setup.ready.platform') }}
              </h3>
              <p class="text-gray-900 dark:text-white">Cloudflare Pages + Worker + D1</p>
            </div>
            <div class="rounded-xl bg-gray-50 p-4 dark:bg-dark-700">
              <h3 class="mb-2 text-sm font-medium text-gray-500 dark:text-dark-400">
                {{ t('setup.ready.adminEmail') }}
              </h3>
              <p class="text-gray-900 dark:text-white">{{ formData.admin.email }}</p>
            </div>
          </div>
        </div>

        <div
          v-if="errorMessage"
          class="mt-6 rounded-xl border border-red-200 bg-red-50 p-4 dark:border-red-800/50 dark:bg-red-900/20"
        >
          <div class="flex items-start gap-3">
            <Icon name="exclamationCircle" size="md" class="flex-shrink-0 text-red-500" />
            <p class="text-sm text-red-700 dark:text-red-400">{{ errorMessage }}</p>
          </div>
        </div>

        <div
          v-if="installSuccess"
          class="mt-6 rounded-xl border border-green-200 bg-green-50 p-4 dark:border-green-800/50 dark:bg-green-900/20"
        >
          <div class="flex items-start gap-3">
            <Icon name="checkCircle" size="md" class="flex-shrink-0 text-green-500" />
            <div>
              <p class="text-sm font-medium text-green-700 dark:text-green-400">
                {{ t('setup.status.completed') }}
              </p>
              <p class="mt-1 text-sm text-green-600 dark:text-green-500">
                {{ t('setup.status.redirecting') }}
              </p>
            </div>
          </div>
        </div>

        <div class="mt-8 flex justify-between">
          <button
            v-if="currentStep > 0 && !installSuccess"
            class="btn btn-secondary"
            @click="currentStep--"
          >
            <Icon name="chevronLeft" size="sm" class="mr-2" :stroke-width="2" />
            {{ t('common.back') }}
          </button>
          <div v-else></div>

          <button
            v-if="currentStep < 2"
            class="btn btn-primary"
            :disabled="!canProceed"
            @click="nextStep"
          >
            {{ t('common.next') }}
            <Icon name="chevronRight" size="sm" class="ml-2" :stroke-width="2" />
          </button>
          <button
            v-else-if="!installSuccess"
            class="btn btn-primary"
            :disabled="installing"
            @click="performInstall"
          >
            <svg
              v-if="installing"
              class="-ml-1 mr-2 h-4 w-4 animate-spin"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            {{ installing ? t('setup.status.installing') : t('setup.status.completeInstallation') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { getSetupStatus, install, type InstallRequest } from '@/api/setup'
import Icon from '@/components/icons/Icon.vue'

const { t } = useI18n()

const steps = computed(() => [
  { id: 'cloudflare', title: t('setup.cloudflare.title') },
  { id: 'admin', title: t('setup.admin.title') },
  { id: 'complete', title: t('setup.ready.title') }
])

const currentStep = ref(0)
const checkingEnvironment = ref(false)
const d1Ready = ref(false)
const installing = ref(false)
const installSuccess = ref(false)
const errorMessage = ref('')
const confirmPassword = ref('')
const formData = reactive<InstallRequest>({
  admin: {
    email: '',
    password: ''
  }
})

const canProceed = computed(() => {
  if (currentStep.value === 0) return d1Ready.value
  if (currentStep.value === 1) {
    return Boolean(
      formData.admin.email &&
      formData.admin.password.length >= 8 &&
      formData.admin.password === confirmPassword.value
    )
  }
  return true
})

onMounted(() => {
  void checkEnvironment()
})

async function checkEnvironment() {
  checkingEnvironment.value = true
  d1Ready.value = false
  errorMessage.value = ''
  try {
    const status = await getSetupStatus()
    if (!status.needs_setup) {
      window.location.replace('/login')
      return
    }
    d1Ready.value = true
  } catch (error: unknown) {
    errorMessage.value = errorText(error, t('setup.cloudflare.bindingMissing'))
  } finally {
    checkingEnvironment.value = false
  }
}

function nextStep() {
  if (!canProceed.value) return
  errorMessage.value = ''
  currentStep.value += 1
}

async function performInstall() {
  installing.value = true
  errorMessage.value = ''
  try {
    await install(formData)
    installSuccess.value = true
    window.setTimeout(() => window.location.replace('/login'), 1200)
  } catch (error: unknown) {
    errorMessage.value = errorText(error, t('setup.status.installFailed'))
  } finally {
    installing.value = false
  }
}

function errorText(error: unknown, fallback: string): string {
  const value = error as {
    response?: { data?: { detail?: string; message?: string; error?: { message?: string } } }
    message?: string
  }
  return value.response?.data?.detail
    || value.response?.data?.message
    || value.response?.data?.error?.message
    || value.message
    || fallback
}
</script>
