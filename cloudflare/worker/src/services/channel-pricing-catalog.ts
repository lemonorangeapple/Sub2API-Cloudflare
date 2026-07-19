// Simplified pricing catalog for common models.
// In production, this would be synced from LiteLLM's pricing catalog.

interface ModelPricingEntry {
    inputPricePerToken: number;
    outputPricePerToken: number;
    cacheWritePrice: number | null;
    cacheReadPrice: number | null;
    imageOutputPrice: number | null;
}

interface ModelPricingResult {
    found: boolean;
    inputPrice?: number;
    outputPrice?: number;
    cacheWritePrice?: number | null;
    cacheReadPrice?: number | null;
    imageOutputPrice?: number | null;
}

const platformToProvider: Record<string, string> = {
    anthropic: "anthropic",
    openai: "openai",
    gemini: "google",
    antigravity: "anthropic",
    grok: "xai",
};

// Partial pricing data for common models (prices per token)
const PRICING_CATALOG: Record<string, Record<string, ModelPricingEntry>> = {
    anthropic: {
        "claude-sonnet-4-20250514": {
            inputPricePerToken: 3e-6, outputPricePerToken: 1.5e-5,
            cacheWritePrice: 3.75e-6, cacheReadPrice: 3e-7, imageOutputPrice: null,
        },
        "claude-sonnet-4": {
            inputPricePerToken: 3e-6, outputPricePerToken: 1.5e-5,
            cacheWritePrice: 3.75e-6, cacheReadPrice: 3e-7, imageOutputPrice: null,
        },
        "claude-3-5-sonnet-20241022": {
            inputPricePerToken: 3e-6, outputPricePerToken: 1.5e-5,
            cacheWritePrice: 3.75e-6, cacheReadPrice: 3e-7, imageOutputPrice: 4e-3,
        },
        "claude-3-5-haiku-20241022": {
            inputPricePerToken: 8e-7, outputPricePerToken: 4e-6,
            cacheWritePrice: 1e-6, cacheReadPrice: 8e-8, imageOutputPrice: 4e-3,
        },
        "claude-3-opus-20240229": {
            inputPricePerToken: 1.5e-5, outputPricePerToken: 7.5e-5,
            cacheWritePrice: 1.875e-5, cacheReadPrice: 1.5e-6, imageOutputPrice: 4e-3,
        },
        "claude-3-haiku-20240307": {
            inputPricePerToken: 2.5e-7, outputPricePerToken: 1.25e-6,
            cacheWritePrice: 3.125e-7, cacheReadPrice: 2.5e-8, imageOutputPrice: 4e-3,
        },
    },
    openai: {
        "gpt-4o-2024-08-06": {
            inputPricePerToken: 2.5e-6, outputPricePerToken: 1e-5,
            cacheWritePrice: 3.125e-6, cacheReadPrice: 1.25e-6, imageOutputPrice: null,
        },
        "gpt-4o-mini-2024-07-18": {
            inputPricePerToken: 1.5e-7, outputPricePerToken: 6e-7,
            cacheWritePrice: 1.875e-7, cacheReadPrice: 7.5e-8, imageOutputPrice: null,
        },
        "gpt-4-turbo-2024-04-09": {
            inputPricePerToken: 1e-5, outputPricePerToken: 3e-5,
            cacheWritePrice: null, cacheReadPrice: null, imageOutputPrice: null,
        },
        "gpt-3.5-turbo-0125": {
            inputPricePerToken: 5e-7, outputPricePerToken: 1.5e-6,
            cacheWritePrice: null, cacheReadPrice: null, imageOutputPrice: null,
        },
    },
    google: {
        "gemini-2.0-flash-exp": {
            inputPricePerToken: 1e-7, outputPricePerToken: 4e-7,
            cacheWritePrice: null, cacheReadPrice: 2.5e-8, imageOutputPrice: null,
        },
        "gemini-1.5-pro-002": {
            inputPricePerToken: 1.25e-6, outputPricePerToken: 5e-6,
            cacheWritePrice: null, cacheReadPrice: 3.125e-7, imageOutputPrice: null,
        },
        "gemini-1.5-flash-002": {
            inputPricePerToken: 7.5e-8, outputPricePerToken: 3e-7,
            cacheWritePrice: null, cacheReadPrice: 1.875e-8, imageOutputPrice: null,
        },
    },
    xai: {
        "grok-2-1212": {
            inputPricePerToken: 2e-6, outputPricePerToken: 1e-5,
            cacheWritePrice: null, cacheReadPrice: null, imageOutputPrice: null,
        },
        "grok-beta": {
            inputPricePerToken: 5e-6, outputPricePerToken: 1.5e-5,
            cacheWritePrice: null, cacheReadPrice: null, imageOutputPrice: null,
        },
    },
};

export class ChannelPricingCatalogService {
    getModelPricing(model: string): ModelPricingResult {
        for (const [, models] of Object.entries(PRICING_CATALOG)) {
            if (model in models) {
                const p = models[model];
                return {
                    found: true,
                    inputPrice: p.inputPricePerToken,
                    outputPrice: p.outputPricePerToken,
                    cacheWritePrice: p.cacheWritePrice,
                    cacheReadPrice: p.cacheReadPrice,
                    imageOutputPrice: p.imageOutputPrice,
                };
            }
        }
        return { found: false };
    }

    listModelNamesByPlatform(platform: string): string[] {
        const provider = platformToProvider[platform];
        if (!provider) return [];
        const models = PRICING_CATALOG[provider];
        if (!models) return [];
        return Object.keys(models);
    }
}
